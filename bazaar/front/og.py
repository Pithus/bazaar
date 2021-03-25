import base64
from io import BytesIO
from tempfile import NamedTemporaryFile

from django.conf import settings
from elasticsearch import Elasticsearch
from PIL import Image, ImageFont, ImageDraw, ImageColor

from bazaar.front.utils import generate_world_map


def rounded_rectangle(image_draw: ImageDraw, xy, corner_radius, fill=None, outline=None):
    upper_left_point = xy[0]
    bottom_right_point = xy[1]
    image_draw.rectangle(
        [
            (upper_left_point[0], upper_left_point[1] + corner_radius),
            (bottom_right_point[0], bottom_right_point[1] - corner_radius)
        ],
        fill=fill,
        outline=outline
    )
    image_draw.rectangle(
        [
            (upper_left_point[0] + corner_radius, upper_left_point[1]),
            (bottom_right_point[0] - corner_radius, bottom_right_point[1])
        ],
        fill=fill,
        outline=outline
    )
    image_draw.pieslice([upper_left_point, (upper_left_point[0] + corner_radius * 2, upper_left_point[1] + corner_radius * 2)],
                        180,
                        270,
                        fill=fill,
                        outline=outline
                        )
    image_draw.pieslice([(bottom_right_point[0] - corner_radius * 2, bottom_right_point[1] - corner_radius * 2), bottom_right_point],
                        0,
                        90,
                        fill=fill,
                        outline=outline
                        )
    image_draw.pieslice([(upper_left_point[0], bottom_right_point[1] - corner_radius * 2), (upper_left_point[0] + corner_radius * 2, bottom_right_point[1])],
                        90,
                        180,
                        fill=fill,
                        outline=outline
                        )
    image_draw.pieslice([(bottom_right_point[0] - corner_radius * 2, upper_left_point[1]), (bottom_right_point[0], upper_left_point[1] + corner_radius * 2)],
                        270,
                        360,
                        fill=fill,
                        outline=outline
                        )


def generate_og_card(sha256, fp):
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
    try:
        result = es.get(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256)['_source']

        tabs = [
            {
                'text': '\uf03a',
                'value': len(result['permissions']),
                'danger': False,
            },
            {
                'text': '\uf1ab',
                'value': len(result['activities']),
                'danger': False,
            },
            {
                'text': '\uf085',
                'value': len(result['services']),
                'danger': False,
            },
            {
                'text': '\uf2a2',
                'value': len(result['receivers']),
                'danger': False,
            },
            {
                'text': '\uf0ac',
                'value': len(result['domains_analysis']),
                'danger': False,
            },
        ]

        if 'vt' in result and 'malicious' in result['vt']:
            if result['vt']['malicious'] > 1:
                tabs.append({
                    'text': '\uf188',
                    'value': '%s/%s' % (result['vt']['malicious'], result['vt']['total']),
                    'danger': True,
                })

        icon_size = (200,200)
        map_size = (1000,360)
        fa = ImageFont.truetype('bazaar/static/fonts/font-awesome/webfonts/fa-solid-900.ttf', 28)
        fa_48 = ImageFont.truetype('bazaar/static/fonts/font-awesome/webfonts/fa-solid-900.ttf', 48)
        font_18 = ImageFont.truetype('bazaar/static/fonts/opensans/OpenSans-Regular.ttf', 28)
        font_24 = ImageFont.truetype('bazaar/static/fonts/opensans/OpenSans-Regular.ttf', 34)
        font_48 = ImageFont.truetype('bazaar/static/fonts/opensans/OpenSans-Regular.ttf', 48)

        white = (255, 255, 255)
        gray = (89, 89, 89)
        purple_primary = (89, 49, 150)
        purple_secondary = (169, 145, 212)
        purple_faded = (238, 233, 246)
        red_primary = (114, 28, 36)
        red_secondary = (220, 53, 69)
        red_faded = (248, 215, 218)

        draw_icon = False
        map_drawn = False
        if result['icon_base64']:
            try:
                icon = Image.open(BytesIO(base64.b64decode(result['icon_base64'])))
                icon.thumbnail(icon_size, Image.ANTIALIAS)
                draw_icon = True
            except Exception:
                pass

        with Image.open('bazaar/static/images/card_w.png') as im:
            top = 40
            left = 40
            if draw_icon:
                im.paste(icon, (40, top), icon)
                left += icon.width+10

            with NamedTemporaryFile() as tmp_png:
                generate_world_map(result['domains_analysis'], to_png=True, fp=tmp_png.name)
                try:
                    map = Image.open(tmp_png.name)
                    map.thumbnail(map_size, Image.ANTIALIAS)
                    im.paste(map, box=(int((im.width-map.width)/2), 300))
                    map_drawn = True
                except Exception:
                    pass

            draw = ImageDraw.Draw(im)

            # Handle
            draw.text((left, top), result['handle'], font=font_24, fill=purple_primary)

            # SHA256
            top += 50
            draw.text((left, top), '#', font=font_18, fill=gray)
            draw.text((left+20, top), result['sha256'], font=font_18, fill=purple_primary)

            # Tabs
            top += 70
            tab_width = int(((im.width - 2*40) / len(tabs)) - 2 * len(tabs))
            left_inc = (im.width - 2*40 - len(tabs)*tab_width) / (len(tabs)-1)
            tab_left = 40
            tab_height = 120
            for tab in tabs:
                bg_color, fg_color, md_color = purple_faded, purple_primary, purple_secondary
                if tab['danger']:
                    bg_color, fg_color, md_color = red_faded, red_primary, red_secondary
                rounded_rectangle(draw, [(tab_left, top), (tab_left+tab_width, top+tab_height)], 10, fill=bg_color)
                draw.text((tab_left+10, top+10), tab['text'], font=fa_48, fill=md_color)
                w,h = font_48.getsize(str(tab['value']))
                txt_left = tab_left+tab_width/2-w/2
                draw.text((txt_left, top+50), str(tab['value']), font=font_48, fill=fg_color)
                tab_left += tab_width+int(left_inc)

            top += 80
            try:
                threat = result['malware_bazaar']['vendor_intel']['ReversingLabs']['threat_name']
                w,h = font_48.getsize(threat)
                txt_left = im.width/2-w/2
                txt_top = top + (im.height-top)/2-h/2
                draw.text((txt_left, txt_top), threat, font=font_48, fill=red_secondary)
            except Exception:
                pass


            im.save(fp, "PNG")


    except Exception as e:
        raise e
