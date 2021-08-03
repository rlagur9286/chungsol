import logging
import os
from django.shortcuts import render

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(
    format="[%(name)s][%(asctime)s] %(message)s",
    handlers=[logging.StreamHandler()],
    level=logging.DEBUG
)
logger = logging.getLogger(__name__)


def render_page(request):
    str_args = request.POST.urlencode()
    dict_args = request.POST.dict()

    return render(request, 'index.html', {})