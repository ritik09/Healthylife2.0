from quickstart.serializers import UserSerializer1,UserSerializer2

def jwt_response_payload_handler(token, user=None, request=None):
    user = UserSerializer1(user, context={'request': request}).data
    return {
        'token': token,
        # 'userid': user['id'],
        'username':user['username']
    }
# def jwt_response_payload_handler(token, user=None, request=None):
#     user = UserSerializer2(user, context={'request': request}).data
#     return {
#         'token': token,
#         'userid': user['id'],
#         'username':user['username']
#     }