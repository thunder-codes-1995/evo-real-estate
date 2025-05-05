from typing import List, Optional

from fastapi import APIRouter, Request, status, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

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


@router.get("/get/documents", response_description="Get all documents from the specified collection")
async def get_collection_data(request: Request, collection: str):
    # Validate that the collection exists in the MongoDB database
    if collection not in await request.app.mongodb.list_collection_names():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Collection '{collection}' not found")

    # Retrieve documents from the specified collection
    documents = await request.app.mongodb[collection].find().to_list(None)

    return build_response(status.HTTP_200_OK, result=documents, message="success")


class ProjectFilterRequest(BaseModel):
    property_type_ids: Optional[List[str]] = None
    property_sub_type_ids: Optional[List[str]] = None
    unittype_ids: Optional[List[str]] = None
    amenity_ids: Optional[List[str]] = None
    min_price: Optional[int] = None
    max_price: Optional[int] = None
    cities: Optional[List[str]] = None
    status: Optional[List[str]] = None

    def has_filters(self) -> bool:
        return any(
            [
                self.property_type_ids,
                self.property_sub_type_ids,
                self.unittype_ids,
                self.amenity_ids,
                self.min_price is not None,
                self.max_price is not None,
                self.cities,
                self.status,
            ]
        )


@router.post("/get", response_description="Get all projects")
async def get_projects(
        request: Request,
        filters: Optional[ProjectFilterRequest] = None,  # Make filters optional
        order_by: Optional[str] = None,  # Make order_by optional
):
    db = request.app.mongodb

    if not filters.has_filters():
        if order_by == "-created_at":
            ordering = -1
        else:
            ordering = 1

        projects = await db.projects.find({}).sort("created_at", ordering).to_list(None)

        # Add additional data to projects
        projects = await add_project_additional_data(request, projects)

        return build_response(status.HTTP_200_OK, result=projects, message="success")

    # Initialize a list to hold all sets of project IDs from different filters
    project_id_sets = []

    # Query project_property_type collection if property_type_ids are provided
    if filters.property_type_ids:
        project_property_type_ids = await db.project_property_type.find(
            {"related_id": {"$in": filters.property_type_ids}},  # Query against list
            {"project_id": 1}
        ).to_list(None)
        property_type_project_ids = set([item['project_id'] for item in project_property_type_ids])
        project_id_sets.append(property_type_project_ids)

    # Query project_sub_type collection if property_sub_type_ids are provided
    if filters.property_sub_type_ids:
        project_sub_type_ids = await db.project_sub_type.find(
            {"related_id": {"$in": filters.property_sub_type_ids}},  # Query against list
            {"project_id": 1}
        ).to_list(None)
        sub_type_project_ids = set([item['project_id'] for item in project_sub_type_ids])
        project_id_sets.append(sub_type_project_ids)

    # Query project_unittype collection if unittype_ids are provided
    if filters.unittype_ids:
        project_unittype_ids = await db.project_unittype.find(
            {"related_id": {"$in": filters.unittype_ids}},  # Query against list
            {"project_id": 1}
        ).to_list(None)
        unittype_project_ids = set([item['project_id'] for item in project_unittype_ids])
        project_id_sets.append(unittype_project_ids)

    # Query project_amenities collection if amenity_ids are provided
    if filters.amenity_ids:
        project_amenity_ids = await db.project_amenities.find(
            {"related_id": {"$in": filters.amenity_ids}},  # Query against list of amenity IDs
            {"project_id": 1}
        ).to_list(None)
        amenity_project_ids = set([item['project_id'] for item in project_amenity_ids])
        project_id_sets.append(amenity_project_ids)

    # Take the intersection of all sets to get common project IDs
    if project_id_sets:
        project_ids = list(set.intersection(*project_id_sets))
    else:
        project_ids = []

    # Query projects collection with the filtered project_ids
    project_filter = {"_id": {"$in": project_ids}} if project_ids else {}

    # Apply price filter if min_price and/or max_price are provided
    if filters.min_price is not None:
        project_filter["price_min"] = {"$gte": filters.min_price}
    if filters.max_price is not None:
        project_filter["price_min"] = {"$lte": filters.max_price}

    if filters.cities:
        project_filter["city"] = {"$in": filters.cities}

    if filters.status:
        project_filter["status"] = {"$in": filters.status}

    if filters.has_filters() and not project_filter and not project_ids:
        return build_response(status.HTTP_200_OK, result=[], message="success")

    if order_by == "-created_at":
        ordering = -1
    else:
        ordering = 1

    projects = await db.projects.find(project_filter).sort("created_at", ordering).to_list(None)

    # Add additional data to projects
    projects = await add_project_additional_data(request, projects)

    return build_response(status.HTTP_200_OK, result=projects, message="success")


@router.get("/search")
async def search_projects(request: Request, search: str):
    # Define a regex query to search in all text-based fields
    search_query = {
        "$or": [
            {"name": {"$regex": search, "$options": "i"}},
            {"area_min": {"$regex": search, "$options": "i"}},
            {"area_max": {"$regex": search, "$options": "i"}},
            {"city": {"$regex": search, "$options": "i"}},
            {"status": {"$regex": search, "$options": "i"}},
            {"developer_name": {"$regex": search, "$options": "i"}}
        ]
    }
    projects_collection = request.app.mongodb["projects"]
    projects = await projects_collection.find(search_query).to_list()
    # Add additional data to projects
    projects = await add_project_additional_data(request, projects)
    return build_response(status.HTTP_200_OK, result=projects, message="success")
