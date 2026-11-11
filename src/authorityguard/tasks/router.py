from typing import Annotated

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from authorityguard.storage.db import get_session
from authorityguard.storage.models import Task, TaskStatus
from authorityguard.storage.pagination import PageDep
from authorityguard.tasks import service
from authorityguard.tasks.schemas import TaskCreate, TaskRead, TaskStatusUpdate

router = APIRouter(prefix="/v1", tags=["tasks"])
SessionDep = Annotated[Session, Depends(get_session)]


@router.post("/tasks", response_model=TaskRead, status_code=201)
def create_task(data: TaskCreate, session: SessionDep) -> Task:
    return service.create_task(session, data)


@router.get("/tasks", response_model=list[TaskRead])
def list_tasks(
    session: SessionDep,
    page: PageDep,
    principal_user_id: str | None = None,
    status: TaskStatus | None = None,
) -> list[Task]:
    query = select(Task).order_by(Task.created_at, Task.id)
    if principal_user_id:
        query = query.where(Task.principal_user_id == principal_user_id)
    if status:
        query = query.where(Task.status == status)
    return list(session.exec(query.offset(page.offset).limit(page.limit)))


@router.get("/tasks/{task_id}", response_model=TaskRead)
def get_task(task_id: str, session: SessionDep) -> Task:
    return service.get_task(session, task_id)


@router.post("/tasks/{task_id}/status", response_model=TaskRead)
def set_task_status(task_id: str, data: TaskStatusUpdate, session: SessionDep) -> Task:
    return service.set_task_status(session, task_id, data.status)
