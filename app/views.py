import logging
import os
from django.shortcuts import render
from django.core.exceptions import ObjectDoesNotExist
from .models import Image
from django.forms.models import model_to_dict


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(
    format="[%(name)s][%(asctime)s] %(message)s",
    handlers=[logging.StreamHandler()],
    level=logging.DEBUG
)
logger = logging.getLogger(__name__)


def render_page(request):
    main_img_ist = []
    for idx in range(1, 4):
        try:
            img = Image.objects.get(title="main{}".format(idx))
            img = model_to_dict(img)
        except ObjectDoesNotExist:
            img = None
        main_img_ist.append(img)
    return render(request, 'index.html', {
        "main_img_ist": main_img_ist
    })