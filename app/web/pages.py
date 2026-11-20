from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"
templates = Jinja2Templates(directory=WEB_DIR / "templates")

router = APIRouter(include_in_schema=False)


def _page(name: str) -> object:
    async def render(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, name)

    return render


router.add_api_route("/", _page("inicio.html"), response_class=HTMLResponse)
router.add_api_route("/verificar", _page("verificar.html"), response_class=HTMLResponse)
router.add_api_route("/panel", _page("panel.html"), response_class=HTMLResponse)
router.add_api_route("/privacidad", _page("privacidad.html"), response_class=HTMLResponse)
