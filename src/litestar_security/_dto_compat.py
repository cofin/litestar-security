"""Access Litestar's private DTO backend extension points in one place.

Litestar does not publicly export the backend hooks required to give generated
transfer models stable names or to compose a DTO for union response types. Keep
those imports here until Litestar exposes the required extension API.
"""

__all__ = ("DTOBackend", "DTOCodegenBackend", "TransferDTOFieldDefinition", "build_annotation_for_backend")

from litestar.dto._backend import DTOBackend, build_annotation_for_backend
from litestar.dto._codegen_backend import DTOCodegenBackend
from litestar.dto._types import TransferDTOFieldDefinition
