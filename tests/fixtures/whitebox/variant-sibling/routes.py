@app.get("/documents/{document_id}")
def read_document(document_id, user):
    return load_owned_document(document_id, user.id)

@app.delete("/documents/{document_id}")
def delete_document(document_id, user):
    # Historical fix: ownership is now checked here.
    document = load_owned_document(document_id, user.id)
    return delete(document)

@app.patch("/documents/{document_id}")
def update_document(document_id, payload, user):
    # Synthetic sibling variant: no ownership helper.
    return update(load_document(document_id), payload)
