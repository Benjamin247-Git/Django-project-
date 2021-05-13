from django.shortcuts import render, redirect, reverse
from rest_framework import generics, status, views, permissions
from .serializers import RegisterSerializer, SetNewPasswordSerializer, UserCrudSerializer, ResetPasswordEmailRequestSerializer, EmailVerificationSerializer, LoginSerializer, LogoutSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .renderers import UserRenderer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
from django.shortcuts import redirect
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.http import HttpResponsePermanentRedirect
import os
from cryptography.fernet import Fernet


class CustomRedirect(HttpResponsePermanentRedirect):

    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']

import random
import string


def get_random_alphanumeric_string(length):
    letters_and_digits = string.ascii_letters + string.digits
    result_str = ''.join((random.choice(letters_and_digits) for i in range(length)))
    return result_str


class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        user = request.data

        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        password = serializer.validated_data['password']
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        email_token = get_random_alphanumeric_string(80)
        user.email_token = email_token
        key = Fernet.generate_key()
        f = Fernet(key)
        token = f.encrypt(password.encode())
        user.password_string = token.decode()
        user.key = key.decode()
        current_site = "divineword.life/email-verification/"
        relativeLink = f"{user_data['email']}/"
        absurl = 'https://'+current_site+relativeLink+email_token
        email_body = 'Hi '+user.username + \
            ' Use the link below to verify your email \n' + absurl
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Verify your email'}
        user.save()

        Util.send_email(data)
        return Response(user_data, status=status.HTTP_201_CREATED)

@api_view(['GET'])
def resend_verification(request, email):
    user = User.objects.get(email=email)

    if user:
        if not user.is_verified:

            email_token = get_random_alphanumeric_string(80)
            user.email_token = email_token
            user.save()

            current_site = "divineword.life/email-verification/"
            relativeLink = f"{user.email}/"
            absurl = 'https://'+current_site+relativeLink+email_token
            email_body = 'Hi '+user.username + \
                ' Use the link below to verify your email \n' + absurl
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Verify your email'}
            Util.send_email(data)
            return Response({'data': "Verification Email Sent"}, status=status.HTTP_200_OK)
        else:
            return Response({'data': "Email already verified"}, status=status.HTTP_200_OK)

    else:
        return Response({'error': 'Email Not Found'}, status=status.HTTP_404_NOT_FOUND)

from .serializers import UserPasswordSerializer, PassSerializer
@api_view(['GET'])
def reset_pass(request, email):
    user = User.objects.get(email=email)

    if user.is_verified:

        email_token = get_random_alphanumeric_string(80)
        user.email_token = email_token
        user.save()

        current_site = "divineword.life/reset-password/"
        relativeLink = f"{user.email}/"
        absurl = 'https://'+current_site+relativeLink+email_token
        email_body = 'Hi '+user.username + \
            ' Use the link below to to reset your password. If you did no initialize this, please do ignore. \n' + absurl
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Reset your password'}
        Util.send_email(data)
    return Response({'success': "Reset Password Email Sent"}, status=status.HTTP_200_OK)
    #     else:
    #         return Response({'error': "Email Not Verified Yet"}, status=status.HTTP_200_OK)
    #
    # else:
    #     return Response({'error': 'Email Not Found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
def confirm_reset_pass(request, email, token):
    user = User.objects.get(email=email, email_token=token)
    serializer = PassSerializer(user, data=request.data)

    if user:
        if serializer.is_valid():
            password = serializer.validated_data['password']
            key = user.key.encode()
            f = Fernet(key)
            user.set_password(password)
            token = f.encrypt(password.encode())
            user.password_string = token.decode()
            user.email_token = ""
            if user.auth_provider != "email":
                user.auth_provider = "email"
            user.save()

            return Response({'success': "Your password has been changed, you may now login"})
        elif user.is_verified:
            return Response({'error': "Email is already verified"}, status=status.HTTP_400_BAD_REQUEST)

    else:
        return Response({'error': "Invalid verification code or user with this email does not exist.."}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user_details(request):
    user = request.user
    usr = User.objects.filter(username=user.username)
    array = ["4r5e", "5h1t", "5hit", "a55", "anal", "anus", "ar5e", "arrse", "arse", "ass", "ass-fucker", "asses", "assfucker", "assfukka", "asshole", "assholes", "asswhole",
             "a_s_s", "b!tch", "b00bs", "b17ch", "b1tch", "ballbag", "balls", "ballsack", "bastard", "beastial", "beastiality", "bellend", "bestial", "bestiality", "bi+ch",
             "biatch", "bitch", "bitcher", "bitchers", "bitches", "bitchin", "bitching", "bloody", "blow job", "blowjob", "blowjobs", "boiolas", "bollock", "bollok", "boner",
             "boob", "boobs", "booobs", "boooobs", "booooobs", "booooooobs", "breasts", "buceta", "bugger", "bum", "bunny fucker", "butt", "butthole", "buttmuch", "buttplug",
             "c0ck", "c0cksucker", "carpet muncher", "cawk", "chink", "cipa", "cl1t", "clit", "clitoris", "clits", "cnut", "cock", "cock-sucker", "cockface", "cockhead",
             "cockmunch", "cockmuncher", "cocks", "cocksuck", "cocksucked", "cocksucker", "cocksucking", "cocksucks", "cocksuka", "cocksukka", "cok", "cokmuncher", "coksucka",
             "coon", "cox", "crap", "cum", "cummer", "cumming", "cums", "cumshot", "cunilingus", "cunillingus", "cunnilingus", "cunt", "cuntlick", "cuntlicker", "cuntlicking",
             "cunts", "cyalis", "cyberfuc", "cyberfuck", "cyberfucked", "cyberfucker", "cyberfuckers", "cyberfucking", "d1ck", "damn", "dick", "dickhead", "dildo", "dildos",
             "dink", "dinks", "dirsa", "dlck", "dog-fucker", "doggin", "dogging", "donkeyribber", "doosh", "duche", "dyke", "ejaculate", "ejaculated", "ejaculates",
             "ejaculating", "ejaculatings", "ejaculation", "ejakulate", "f u c k", "f u c k e r", "f4nny", "fag", "fagging", "faggitt", "faggot", "faggs", "fagot", "fagots",
             "fags", "fanny", "fannyflaps", "fannyfucker", "fanyy", "fatass", "fcuk", "fcuker", "fcuking", "feck", "fecker", "felching", "fellate", "fellatio", "fingerfuck",
             "fingerfucked", "fingerfucker", "fingerfuckers", "fingerfucking", "fingerfucks", "fistfuck", "fistfucked", "fistfucker", "fistfuckers", "fistfucking", "fistfuckings",
             "fistfucks", "flange", "fook", "fooker", "fuck", "fucka", "fucked", "fucker", "fuckers", "fuckhead", "fuckheads", "fuckin", "fucking", "fuckings",
             "fuckingshitmotherfucker", "fuckme", "fucks", "fuckwhit", "fuckwit", "fudge packer", "fudgepacker", "fuk", "fuker", "fukker", "fukkin", "fuks", "fukwhit", "fukwit",
             "fux", "fux0r", "f_u_c_k", "gangbang", "gangbanged", "gangbangs", "gaylord", "gaysex", "goatse", "God", "god-dam", "god-damned", "goddamn", "goddamned", "hardcoresex",
             "hell", "heshe", "hoar", "hoare", "hoer", "homo", "hore", "horniest", "horny", "hotsex", "jack-off", "jackoff", "jap", "jerk-off", "jism", "jiz", "jizm", "jizz", "kawk",
             "knob", "knobead", "knobed", "knobend", "knobhead", "knobjocky", "knobjokey", "kock", "kondum", "kondums", "kum", "kummer", "kumming", "kums", "kunilingus", "l3i+ch",
             "l3itch", "labia", "lust", "lusting", "m0f0", "m0fo", "m45terbate", "ma5terb8", "ma5terbate", "masochist", "master-bate", "masterb8", "masterbat*", "masterbat3",
             "masterbate", "masterbation", "masterbations", "masturbate", "mo-fo", "mof0", "mofo", "mothafuck", "mothafucka", "mothafuckas", "mothafuckaz", "mothafucked",
             "mothafucker", "mothafuckers", "mothafuckin", "mothafucking", "mothafuckings", "mothafucks", "mother fucker", "motherfuck", "motherfucked", "motherfucker",
             "motherfuckers", "motherfuckin", "motherfucking", "motherfuckings", "motherfuckka", "motherfucks", "muff", "mutha", "muthafecker", "muthafuckker", "muther",
             "mutherfucker", "n1gga", "n1gger", "nazi", "nigg3r", "nigg4h", "nigga", "niggah", "niggas", "niggaz", "nigger", "niggers", "nob", "nob jokey", "nobhead", "nobjocky",
             "nobjokey", "numbnuts", "nutsack", "orgasim", "orgasims", "orgasm", "orgasms", "p0rn", "pawn", "pecker", "penis", "penisfucker", "phonesex", "phuck", "phuk", "phuked",
             "phuking", "phukked", "phukking", "phuks", "phuq", "pigfucker", "pimpis", "piss", "pissed", "pisser", "pissers", "pisses", "pissflaps", "pissin", "pissing", "pissoff",
             "poop", "porn", "porno", "pornography", "pornos", "prick", "pricks", "pron", "pube", "pusse", "pussi", "pussies", "pussy", "pussys", "rectum", "retard", "rimjaw",
             "rimming", "s hit", "s.o.b.", "sadist", "schlong", "screwing", "scroat", "scrote", "scrotum", "semen", "sex", "sh!+", "sh!t", "sh1t", "shag", "shagger", "shaggin",
             "shagging", "shemale", "shi+", "shit", "shitdick", "shite", "shited", "shitey", "shitfuck", "shitfull", "shithead", "shiting", "shitings", "shits", "shitted", "shitter",
             "shitters", "shitting", "shittings", "shitty", "skank", "slut", "sluts", "smegma", "smut", "snatch", "son-of-a-bitch", "spac", "spunk", "s_h_i_t", "t1tt1e5", "t1tties",
             "teets", "teez", "testical", "testicle", "tit", "titfuck", "tits", "titt", "tittie5", "tittiefucker", "titties", "tittyfuck", "tittywank", "titwank", "tosser", "turd",
             "tw4t", "twat", "twathead", "twatty", "twunt", "twunter", "v14gra", "v1gra", "vagina", "viagra", "vulva", "w00se", "wang", "wank", "wanker", "wanky", "whoar", "whore",
             "willies", "willy", "xrated", "xxx"]

    # if user.is_author:
    serializer = UserCrudSerializer(user, data=request.data, partial=True)
    if serializer.is_valid():
        first_name = serializer.validated_data['first_name']

        last_name = serializer.validated_data['last_name']

        country = serializer.validated_data['country']

        facebook = serializer.validated_data['facebook']

        twitter = serializer.validated_data['twitter']
        youtube =  serializer.validated_data['youtube']
        instagram = serializer.validated_data['instagram']
        state = serializer.validated_data['state']
        if serializer.validated_data['about']:
            about = serializer.validated_data['about']
        else:
            about = ""
        verify_author = serializer.validated_data['verify_author']
        mobile_no = serializer.validated_data['mobile_no']

        if any(c in first_name.casefold() or c in last_name.casefold() for c in array):
            if user.violation <= 5:
                usr.update(violation=user.violation + 1)
                return Response("Your first name or last name contained foul words or language. Your account will be disabled if you keep trying to use those words as your name.", status=status.HTTP_400_BAD_REQUEST)
            else:
                usr.update(violation=user.violation + 1, is_active=False)
                return Response("Account Disabled", status=status.HTTP_400_BAD_REQUEST)
        else:
            usr.update(first_name=first_name, last_name=last_name, country=country, facebook=facebook,
                       twitter=twitter, youtube=youtube, instagram=instagram, state=state, about=about,
                       verify_author=verify_author,
                       mobile_no=mobile_no)
            return Response({"data": "Profile updated"}, status=status.HTTP_200_OK)

    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)

    # else:
    #     return Response({'data': 'User not an author'}, status=status.HTTP_400_BAD_REQUEST)


from .serializers import UserImageSerializer
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user_image(request):
    user = request.user

    if user.is_author:
        serializer = UserImageSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"data": "Image updated"}, status=status.HTTP_200_OK)

        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

    else:
        return Response({'data': 'User not an author'}, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def email_verification(request, email, token):
    user = User.objects.get(email=email, email_token=token)

    if user:
        if not user.is_verified:
            user.is_verified = True
            user.email_token = "Xvafd44GsD0BiKl8pfxa-86x_-9s/i!m"
            user.save()

            return Response({'data': "Your email is now verified you may now login"})
        elif user.is_verified:
            return Response({'error': "Email is already verified"}, status=status.HTTP_400_BAD_REQUEST)

    else:
        return Response({'error': "Invalid verification code or user with this email does not exist.."}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            redirect_url = request.data.get('redirect_url', '')
            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                absurl+"?redirect_url="+redirect_url
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            Util.send_email(data)
            return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'User with this email does not exist!'}, status=status.HTTP_404_NOT_FOUND)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):

        redirect_url = request.GET.get('redirect_url')

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                if len(redirect_url) > 3:
                    return CustomRedirect(redirect_url+'?token_valid=False')
                else:
                    return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

            if redirect_url and len(redirect_url) > 3:
                return CustomRedirect(redirect_url+'?token_valid=True&message=Credentials Valid&uidb64='+uidb64+'&token='+token)
            else:
                return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

        except DjangoUnicodeDecodeError as identifier:
            try:
                if not PasswordResetTokenGenerator().check_token(user):
                    return CustomRedirect(redirect_url+'?token_valid=False')
                    
            except UnboundLocalError as e:
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)



class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer

    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)

@api_view(['GET'])
def check_email(request, email):
    user = User.objects.filter(email=email).exists()

    if user:
        return Response(True)
    else:
        return Response(False)


from django.contrib.auth.decorators import login_required

@login_required
def author_verification_list(request):
    if request.user.is_superuser:
        author_list = User.objects.filter(is_verified=True, is_author=False, verify_author=True)

        return render(request,'authentication/index.html', {"author_list": author_list}, )
    else:
        return "User not a super user.."


from django.http import HttpResponseRedirect

@login_required
def author_verified(request, username):
    user = User.objects.get(username=username)

    if not user.is_author and request.user.is_superuser:
        user.is_author = True
        user.save()

        email_body = f"Hello {user.username}, \n   We are glad to inform you that you have been verified as an author. You can now post articles and audio sermons. Other users can also " \
                     f"now follow you to see your new posts. Below are some pointers to note when creating articles and audio sermons.\n" \
                     f"   Users would relate well to articles and audio sermons with clear and sharp pictures better than the ones with blurry or unappealing pictures. You can take your own pictures or just choose from the thousands of pictures avaliable on unsplash.com, there you can search pictures based on the title of your article or audio sermon. Another thing to consider is your grammar when writing your articles. This can be made easy by installing Grammarly for your browser on pc or, for your mobile devices as a keyboard. This greatly improves your writing, spelling, and grammar. Sharing is caring, share your articles and audio sermons with others so, they too can see the world for God we are building. Share the gospel with the world. \n" \
                     f"\nKelvin Sajere(Founder Divine Word)"

        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'You are now an author'}
        Util.send_email(data)
        return HttpResponseRedirect(reverse('author-verification'))


