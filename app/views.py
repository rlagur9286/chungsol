import logging
import os
import random
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

    main_img_list = []
    ###################################################
    # MAIN 이미지
    ###################################################
    for idx in range(1, 5):
        try:
            img = Image.objects.get(title="main{}".format(idx))
            img = model_to_dict(img)
        except ObjectDoesNotExist:
            img = None
        main_img_list.append(img)

    spring_img_list = []
    summer_img_list = []
    autumm_img_list = []
    winter_img_list = []
    ###################################################
    # 계절별 이미지
    ###################################################
    try:
        # 봄
        images = Image.objects.filter(title__startswith="spring_")
        for img in images:
            img = model_to_dict(img)
            spring_img_list.append(img)
        random.shuffle(spring_img_list)

        # 여름
        images = Image.objects.filter(title__startswith="summer_")
        for img in images:
            img = model_to_dict(img)
            summer_img_list.append(img)
        random.shuffle(summer_img_list)

        # 가을
        images = Image.objects.filter(title__startswith="autumm")
        for img in images:
            img = model_to_dict(img)
            autumm_img_list.append(img)
        random.shuffle(autumm_img_list)

        # 겨울
        images = Image.objects.filter(title__startswith="winter_")
        for img in images:
            img = model_to_dict(img)
            winter_img_list.append(img)
        random.shuffle(winter_img_list)
    except ObjectDoesNotExist:
        spring_img_list, summer_img_list, autumm_img_list, winter_img_list = [], [], [], []

    return render(request, 'index.html', {
        "main_img_list": main_img_list,
        "spring_img_list": spring_img_list,
        "summer_img_list": summer_img_list,
        "autumm_img_list": autumm_img_list,
        "winter_img_list": winter_img_list,
    })