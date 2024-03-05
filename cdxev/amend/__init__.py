from .command import register_operation
from .operations import (
    AddBomRefOperation,
    CompositionsOperation,
    DefaultAuthorOperation,
    InferCopyright,
    InferSupplier,
    ProcessLicense,
)

register_operation(AddBomRefOperation())
register_operation(DefaultAuthorOperation())
register_operation(CompositionsOperation())
register_operation(InferSupplier())
register_operation(ProcessLicense())
register_operation(InferCopyright())
