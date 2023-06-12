from .command import register_operation
from .operations import (
    AddBomRefOperation,
    CompositionsOperation,
    DefaultAuthorOperation,
    InferSupplier,
    ReplaceLicenseNameWithId,
)

register_operation(AddBomRefOperation())
register_operation(DefaultAuthorOperation())
register_operation(CompositionsOperation())
register_operation(InferSupplier())
register_operation(ReplaceLicenseNameWithId())
