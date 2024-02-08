from .command import register_operation
from .operations import (
    AddBomRefOperation,
    CompositionsOperation,
    DefaultAuthorOperation,
    InferSupplier,
    ProcessLicense,
    InferCopyright
)

register_operation(AddBomRefOperation())
register_operation(DefaultAuthorOperation())
register_operation(CompositionsOperation())
register_operation(InferSupplier())
register_operation(ProcessLicense())
register_operation(InferCopyright())
