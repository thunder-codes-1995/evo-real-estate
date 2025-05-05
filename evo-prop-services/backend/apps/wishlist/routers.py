from datetime import datetime, timedelta
from uuid import uuid4

from fastapi import APIRouter, Request, status, HTTPException
from fastapi.responses import JSONResponse

from apps.projects.utils import add_project_additional_data

router = APIRouter()


# Helper function for building JSON responses
def build_response(status_code: int, result=None, message=None):
    """
    Build a standardized JSON response.

    Args:
        status_code (int): HTTP status code.
        result (list): Result data.
        message (str): Response message.

    Returns:
        JSONResponse: Constructed JSON response.
    """
    data = {"result": result, "message": message}
    return JSONResponse(status_code=status_code, content=data)


@router.post("/add", response_description="Add Project to Wishlist")
async def add_to_wishlist(request: Request):
    body = await request.json()

    user_id = body.get("user_id")
    project_id = body.get("project_id")

    if not user_id or not project_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="user_id and project_id are required")

    wishlist_collection = request.app.mongodb["wishlist"]

    # Check if project is already in wishlist for the user
    existing_wishlist_item = await wishlist_collection.find_one({"user_id": user_id, "project_id": project_id})

    if existing_wishlist_item:
        return build_response(status.HTTP_200_OK, message="Project already in wishlist")

    # Add the project to the wishlist
    wishlist_item = {
        "_id": str(uuid4()),
        "user_id": user_id,
        "project_id": project_id,
        "created_at": (datetime.now() + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
    }

    result = await wishlist_collection.insert_one(wishlist_item)

    if result.inserted_id:
        return build_response(status.HTTP_200_OK, result=[wishlist_item],
                              message="Project added to wishlist")
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Failed to add project to wishlist")


@router.post("/remove", response_description="Remove Project from Wishlist")
async def remove_from_wishlist(request: Request):
    body = await request.json()

    user_id = body.get("user_id")
    project_id = body.get("project_id")

    if not user_id or not project_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="user_id and project_id are required")

    wishlist_collection = request.app.mongodb["wishlist"]

    # Check if the project is in the user's wishlist
    existing_wishlist_item = await wishlist_collection.find_one({"user_id": user_id, "project_id": project_id})

    if not existing_wishlist_item:
        return build_response(status.HTTP_404_NOT_FOUND, message="Project not found in wishlist")

    # Remove the project from the wishlist
    delete_result = await wishlist_collection.delete_one({"user_id": user_id, "project_id": project_id})

    if delete_result.deleted_count == 1:
        return build_response(status.HTTP_200_OK, message="Project removed from wishlist")
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Failed to remove project from wishlist")

@router.get("/projects", response_description="Get Wishlisted Projects")
async def get_wishlisted_projects(request: Request, user_id: str):
    if not user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="user_id is required")

    wishlist_collection = request.app.mongodb["wishlist"]

    # Fetch all projects wishlisted by the user
    wishlisted_projects = await wishlist_collection.find({"user_id": user_id}).to_list(None)

    if not wishlisted_projects:
        return build_response(status.HTTP_200_OK, result=[], message="No projects found in wishlist")

    project_ids = [item['project_id'] for item in wishlisted_projects]
    project_filter = {"_id": {"$in": project_ids}}

    project_collection = request.app.mongodb["projects"]

    # Extract project IDs or return full items if needed
    projects = await project_collection.find(project_filter).to_list(None)

    # Add additional data to projects
    projects = await add_project_additional_data(request, projects)

    return build_response(status.HTTP_200_OK, result=projects, message="success")


@router.get("/my", response_description="Get Wishlisted Projects")
async def get_wishlisted_projects(request: Request, user_id: str):
    if not user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="user_id is required")

    wishlist_collection = request.app.mongodb["wishlist"]

    # Fetch all projects wishlisted by the user
    wishlisted_projects = await wishlist_collection.find({"user_id": user_id}).to_list(None)

    return build_response(status.HTTP_200_OK, result=wishlisted_projects, message="success")