
from bazaar.core.models import Notification

def get_user_notifications(request):
    if not request.user.is_authenticated:
        return []

    return Notification.objects.filter(user=request.user)


def add_user_notification(user, text_content, redirect_link=None):
    if not user.is_authenticated:
        return False
    
    Notification.objects.create(user=user, text_content=text_content, redirect_link=redirect_link)
    return True


def delete_user_notification(request, notif_id):
    if not request.user.is_authenticated:
        return False
    notifications = Notification.objects.filter(user=request.user, id=notif_id)
    for notif in notifications:
        notif.delete()
    return True


def delete_all_user_notifications(request):
    if not request.user.is_authenticated:
        return False
    notifications = Notification.objects.filter(user=request.user)
    for notif in notifications:
        notif.delete()
    return True