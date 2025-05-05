async def add_project_additional_data(request, projects):
    # Initialize additional data for each project
    for project in projects:
        project_id = project['_id']

        # Fetch related property types
        property_types = await request.app.mongodb["project_property_type"].find({"project_id": project_id}).to_list(None)
        property_type_ids = [pt['related_id'] for pt in property_types]

        # Fetch related property sub types
        property_sub_types = await request.app.mongodb["project_sub_type"].find({"project_id": project_id}).to_list(None)
        property_sub_type_ids = [pst['related_id'] for pst in property_sub_types]

        # Fetch related unit types
        unit_types = await request.app.mongodb["project_unittype"].find({"project_id": project_id}).to_list(None)
        unit_type_ids = [ut['related_id'] for ut in unit_types]

        # Fetch related amenities
        amenities = await request.app.mongodb["project_amenities"].find({"project_id": project_id}).to_list(None)
        amenity_ids = [amenity['related_id'] for amenity in amenities]

        # Build additional data
        project['additional_data'] = {
            "property_types": await request.app.mongodb["property_type"].find({"_id": {"$in": property_type_ids}}).to_list(None),
            "property_sub_types": await request.app.mongodb["property_sub_type"].find({"_id": {"$in": property_sub_type_ids}}).to_list(None),
            "unit_types": await request.app.mongodb["unittype"].find({"_id": {"$in": unit_type_ids}}).to_list(None),
            "amenities": await request.app.mongodb["amenities"].find({"_id": {"$in": amenity_ids}}).to_list(None)
        }
    return projects
