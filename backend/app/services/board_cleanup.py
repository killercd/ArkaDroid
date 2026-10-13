from sqlalchemy.orm import Session

from app.models.authorize import AuthorizeExchange
from app.models.http import HttpExchange
from app.models.show_response import ShowResponseLink


def clear_http_exchanges(db: Session, project_id: int) -> int:
    deleted = db.query(HttpExchange).filter(HttpExchange.project_id == project_id).delete(synchronize_session=False)
    db.query(ShowResponseLink).filter(
        ShowResponseLink.project_id == project_id,
        ShowResponseLink.source_type == "http-exchange",
    ).delete(synchronize_session=False)
    return deleted


def clear_authorize_history(db: Session, project_id: int) -> int:
    deleted = db.query(AuthorizeExchange).filter(AuthorizeExchange.project_id == project_id).delete(synchronize_session=False)
    db.query(ShowResponseLink).filter(
        ShowResponseLink.project_id == project_id,
        ShowResponseLink.source_type == "authorize",
    ).delete(synchronize_session=False)
    return deleted
