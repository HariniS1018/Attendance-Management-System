from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies, decode_token, create_refresh_token
from flask import request, Response, jsonify, redirect, url_for
from flask_restful import Resource, Api, reqparse, abort, fields, marshal_with
import jwt, requests
from amsModel import *
from datetime import datetime, timedelta
from sqlalchemy import and_
import json, random, hashlib
from flask_mail import Message

# app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a long, random string in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=5)
api = Api(app)
jwt = JWTManager(app)

user_fields= {
   'user_id': fields.String,
   'user_name': fields.String,
   'email_id': fields.String,
   'password': fields.String,
   'advisor_year':fields.String,
   'advisor_branch': fields.String,
   'role': fields.String,
}

upPwd_fields= {
   'user_id': fields.String,
   'email_id': fields.String,
   'password': fields.String,
   'otp': fields.String
}

course_fields= {
   'course_code': fields.String,
   'course_name': fields.String,
   'course_type': fields.String,
   'total_credits':fields.Integer,
   'semester_in': fields.Integer
}

enroll_fields = {
    'user_id': fields.String,
    'course_code': fields.String
}

absent_fields = {
    'user_id': fields.String,
    'course_code': fields.String,
    'absent_date': fields.String,
    'absent_hour': fields.String,
    'absent_reason': fields.String,
}

up_status = {
    'status': fields.Integer
}

daily_att_fields = {
    'from_date': fields.String,
    'to_date': fields.String,
    'course_code': fields.String
}

user_login = reqparse.RequestParser()
user_login.add_argument("user_id", type=str, help="user_id is required", required=True)
user_login.add_argument("password", type=str, help="password is required", required=True)
user_login.add_argument("user_name", type=str)
user_login.add_argument("email_id", type=str)
user_login.add_argument("role", type=str)

user_post = reqparse.RequestParser()
user_post.add_argument("user_id", type=str, help="user_id is required", required=True)
user_post.add_argument("user_name", type=str, help="user_name is required", required=True)
user_post.add_argument("email_id", type=str, help="email_id is required", required=True)
user_post.add_argument("role", type=str, help="role is required", required=True)
user_post.add_argument("password", type=str, help="password is required", required=True)
user_post.add_argument("advisor_year", type=str)
user_post.add_argument("advisor_branch", type=str)

user_put = reqparse.RequestParser()
user_put.add_argument("user_id", type=str, help="user_id is required", required=True)
user_put.add_argument("password", type=str)  #, help="password is required", required=True
user_put.add_argument("otp", type=int)      # user_put.add_argument("email_id", type=str)

course_post = reqparse.RequestParser()
course_post.add_argument("course_code", type=str, help="course_code is required", required=True)
course_post.add_argument("course_name", type=str, help="course_name is required", required=True)
course_post.add_argument("course_type", type=str, help="course_type is required", required=True)
course_post.add_argument("total_credits", type=int, help="total_credits is required", required=True)
course_post.add_argument("semester_in", type=int, help="semester_in is required", required=True)

course_get = reqparse.RequestParser()
course_get.add_argument("semester_in", type=int, help="semester_in is required", required=True)

enroll_post = reqparse.RequestParser()
enroll_post.add_argument("course_code", type=str)
enroll_post.add_argument("user_id", type=str)

absent_post = reqparse.RequestParser()
absent_post.add_argument("user_id", type=str, help="user_id is required", required=True)
absent_post.add_argument("course_code", type=str, help="course_code is required", required=True)
absent_post.add_argument("absent_date", type=str, help="absent_date is required", required=True)
absent_post.add_argument("absent_hour", type=str, help="absent_hour is required", required=True)
absent_post.add_argument("absent_reason", type=str, help="absent_reason is required", required=True)

update_status = reqparse.RequestParser()
update_status.add_argument("status",type=int, help="status is required", required=True)

daily_att = reqparse.RequestParser()
daily_att.add_argument("from_date", type=str, help="from_date is required", required=True)
daily_att.add_argument("to_date", type=str, help="to_date is required", required=True)
daily_att.add_argument("course_code", type=str)


def msg_encryption(code):
    result = hashlib.sha256(code.encode())
    encrypted_msg = result.hexdigest()
    return encrypted_msg

def send_otp_email(email, otp):
    msg = Message('Your OTP Code', recipients=[email])
    msg.body = f'Your OTP code is: {otp}'
    mail.send(msg)

@app.before_request
def check_token_expiry_and_refresh():
    # Skip token expiry check for registration, update password and login endpoints
    # if request.endpoint in ['UserRegister', 'UserLogin', 'SendOTPFgtPwd', 'UpdatePassword']:
    #     return None
    
    if request.path in ['/UserRegister', '/UserLogin', '/SendOTPFgtPwd', '/UpdatePassword']:
        return None
    
    # Check token expiry for all other endpoints
    authorization_header = request.headers.get('Authorization')
    if not authorization_header or not authorization_header.startswith('Bearer '):
        return jsonify({'error':'not found'})
        # return redirect('http://127.0.0.1:5000/UserLogin')
    
    try:
        access_token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=['HS256'])
        expiration_time = decoded_token['exp']
        
        if expiration_time < timedelta(minutes=5):
            # Token is about to expire, refresh it
            current_user = decoded_token['identity']
            refresh_token = create_refresh_token(identity=current_user)
            # access_token = create_access_token(identity=current_user)
            return jsonify({'refresh_token': refresh_token}), 200

    except jwt.ExpiredSignatureError:
        # Token has expired, return 401 Unauthorized
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        # Invalid token, return 401 Unauthorized
        return jsonify({'message': 'Invalid token'}), 401
    except Exception as e:
        # Handle other token decoding errors
        return jsonify({'message': 'Error decoding token'}), 500

    return None

class ProtectedResource(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        decoded_token = decode_token(current_user)  # Decoding the JWT token
        
        # Retrieving user_id and user_role from the decoded token
        user_id = decoded_token['user_id']
        user_role = decoded_token['user_role']
        
        length = len(user_id)
        if length != 10 and length != 6:
            return {'message': 'User not found'}, 404
        if length == 10:
            user = student_details.query.filter_by(user_id=user_id).first()
        elif length == 6:
            user = staff_details.query.filter_by(user_id=user_id).first()
        
        if user:
            # Determine user's role
            user_role = user.role
            
            # Check if user has permission to add tasks
            allowed_to_teacher = True if user_role == 'teacher' else False
            
            # Check if user has permission to remove tasks
            allowed_to_student = True if user_role == 'student' else False
            
            allowed_to_advisor = True if user_role == 'advisor' else False
            
            # Return RBAC response
            return jsonify({
                'user_role': user_role,
                'allowed_to_teacher': allowed_to_teacher,
                'allowed_to_student': allowed_to_student,
                'allowed_to_advisor': allowed_to_advisor
            }), 200
        else:
            return {'message': 'User not found'}, 404


# -----------------------------------------------------------------------------------------------------------------------------------------

class UserRegister(Resource):
    @marshal_with(user_fields)      # to store in database for registration
    def post(self):
        args = user_post.parse_args()
        length = len(args["user_id"])
        pwd = msg_encryption(args["password"])
        if length != 10 and length != 6:
            abort(404, message="Enter a valid user id")
        if length == 10:
            user = student_details.query.filter_by(user_id=args["user_id"]).first()
        elif length == 6:
            user = staff_details.query.filter_by(user_id=args["user_id"]).first()
        if user:
            abort(401, message="This User ID is already registered")
        else:
            if length == 10:
                add_user = student_details(user_id = args["user_id"],user_name = args["user_name"],email_id = args["email_id"],password = pwd)
            if length == 6:
                if args["advisor_branch"]:
                    if args["advisor_branch"] == 'CS':
                        ad_class = int(args["advisor_year"] + '23')
                    else:
                        ad_class = int(str(args["advisor_year"]) + '24')
                else:
                    ad_class = 0
                add_user = staff_details(user_id = args["user_id"],user_name = args["user_name"],email_id = args["email_id"],password = pwd, advisor_class=ad_class, role = args['role'])
        db.session.add(add_user)
        db.session.commit()
        email_id = args["email_id"]
        code = random.randint(100001, 999999)
        send_otp_email(email_id, code)
        codeEncrypted = msg_encryption(str(code))
        add_user.otp = codeEncrypted
        db.session.commit()
        return "otp has been sent to your registered mail...", 201
        
    def put(self):
        args = user_put.parse_args()
        length = len(args["user_id"])
        if length == 10:
            user = student_details.query.filter_by(user_id=args["user_id"]).first()
        elif length == 6:
            user = staff_details.query.filter_by(user_id=args["user_id"]).first()
        else:
            abort(404, message="something went wrong")
        user_code = msg_encryption(str(args["otp"]))
        if user_code != user.otp:
            db.session.delete(user)
            db.session.commit()
            return "Invalid otp.... Registration unsuccessful!"
        else:
            user.is_active = 1
            db.session.commit()
            return "Registration successful!", 200


class UserLogin(Resource):
    @marshal_with(user_fields)      # to read from the database for login
    def post(self): 
        args = user_login.parse_args()
        length = len(args["user_id"])
        pwd = msg_encryption(args["password"])
        if length != 10 and length != 6:
            abort(401, message="Enter a valid user id")
        elif length == 10:
            user = db.session.query(student_details).filter(and_(student_details.user_id == args["user_id"],student_details.is_active == 1)).first()
            inactive_user = db.session.query(student_details).filter(and_(student_details.user_id == args["user_id"],student_details.is_active == 0)).first()
            if inactive_user:
                db.session.delete(inactive_user)
                db.session.commit()
            if user:
                user_role = "student"
        elif length == 6:
            user = db.session.query(staff_details).filter(and_(staff_details.user_id == args["user_id"],staff_details.is_active == 1)).first()
            inactive_user = db.session.query(staff_details).filter(and_(staff_details.user_id == args["user_id"],staff_details.is_active == 0)).first()
            if inactive_user:
                db.session.delete(inactive_user)
                db.session.commit()
            if user:
                user_role= user.role
        if user and pwd == user.password:
            token = create_access_token(identity={'user_id': user.user_id, 'user_role': user_role})
            args['password'] = ""
            return jsonify({'token':token})
        else:
            return jsonify({'Authentication Failed': 403})

class SendOTPFgtPwd(Resource):
    @marshal_with(upPwd_fields)
    def post(self):     # to get user_id to check in db and send otp for forgot password
        args = user_put.parse_args()
        length = len(args["user_id"])
        if length != 10 and length != 6:
            abort(404, message="Enter a valid user id")
        elif length == 10:
            user = student_details.query.filter_by(user_id=args["user_id"]).first()
        elif length == 6:
            user = staff_details.query.filter_by(user_id=args["user_id"]).first()
        if not user:
            abort(404, message = "User id doesn't registered, cannot update")
        elif not user.email_id:
            abort(404, "User's mail id is not found")
        email_id = user.email_id
        otp = random.randint(100001, 999999)
        send_otp_email(email_id, otp)
        codeEncrypted = msg_encryption(str(otp))
        user.otp = codeEncrypted
        db.session.commit()
        return Response("{'response': 'otp has been sent to your registered mail...'}", status=200)

class UpdatePassword(Resource):
    @marshal_with(upPwd_fields)
    def post(self):     # to validate otp and update password in the db
        args = user_put.parse_args()
        length = len(args["user_id"])
        if not args["otp"]:
            abort(422, message = "please enter the OTP" )
        if length == 10:
            db_code = db.session.query(student_details).filter(student_details.user_id == args["user_id"]).first()
        elif length == 6:
            db_code = db.session.query(staff_details).filter(staff_details.user_id == args["user_id"]).first()
        else:
            abort(404, message="Invalid user_id")
        user_code = msg_encryption(str(args["otp"]))
        if user_code != db_code.otp:
            abort(402, message= "Invalid OTP")
        return 201
    
    @marshal_with(upPwd_fields)
    def put(self):
        args = user_put.parse_args()
        length = len(args["user_id"])
        if length == 10:
            user = student_details.query.filter_by(user_id=args["user_id"]).first()
        elif length == 6:
            user = staff_details.query.filter_by(user_id=args["user_id"]).first()
        if not args["password"]:
            abort(404, message = "please enter the new password" )
        pwd = msg_encryption(args["password"])
        user.password = pwd
        db.session.commit()
        return "Password has been updated succesfully!",201
    

# -------------------------------------------------------------------------------------------------------------------------- #
    

class CourseRegister(Resource):
    @jwt_required()
    @marshal_with(course_fields)    
    def post(self):     # to store in database when a new course is registered
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_advisor']:
                args = course_post.parse_args()
                is_course = course.query.filter_by(course_code=args["course_code"]).first()
                if is_course:
                    abort(404, message="course already exist")
                add_course = course(course_code=args["course_code"],course_name=args["course_name"],course_type=args["course_type"],total_credits=args["total_credits"],semester_in=args["semester_in"])
                db.session.add(add_course)
                db.session.commit()
                return {"course Registered successfully"},201
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500

    
class CoursesInSem(Resource):
    @jwt_required()
    def get(self,semester_in):      # to list all the courses that are in a particular sem for dropdown
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_advisor']:
                courses = db.session.query(course.course_code,course.course_name).filter(course.semester_in == semester_in)
                course_list = []
                if not courses:
                    abort(404, message="no course registered for this sem")
                for i in courses:
                    course_str = i.course_code + " - " + i.course_name
                    course_list.append(course_str)
                return course_list
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500


class MyStudentList(Resource):
    @jwt_required()
    def get(self,user_id):         # The advisor needs to get the list of her/his students to enroll for a course and also for view forms...
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_advisor']:
                staff = staff_details.query.filter_by(user_id = user_id).first()
                students = db.session.query(student_details.user_id, student_details.user_name).filter(and_(student_details.user_id.cast(Integer) > (staff.advisor_class*10000), student_details.user_id.cast(Integer) < ((staff.advisor_class+1)*10000) )).all()
                student_list = []
                for student in students:
                    count = absence_intimation.query.filter_by(user_id = student.user_id).count() # the count is included for view form page, drop it in enrollment page
                    student_list.append({"user_id":student.user_id,"user_name":student.user_name,"count":count})
                return student_list
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500

        
class MyStudentEnrollment(Resource):
    @jwt_required()
    def post(self):     # to store enrollment details of students done by advisor
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_advisor']:
                input_data = request.get_json()
                for item in input_data:
                    user_id = item["user_id"]
                    course_code = item["course_code"].split(" - ")
                    course_code = course_code[0]
                    existing = student_enrolled.query.filter_by(user_id=user_id, course_code=course_code).first()
                    if not existing:
                        enroll = student_enrolled(user_id=user_id, course_code=course_code)
                        db.session.add(enroll)
                db.session.commit()
                return "Data stored successfully", 201
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500


class OverallAttendanceforAdvisor(Resource):
    @jwt_required()
    def post(self,user_id):     # to view attendance % hold by every student of the advisor's class
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_advisor']:
                staff = staff_details.query.filter_by(user_id = user_id).first()
                students = db.session.query(student_details.user_id, student_details.user_name).filter(and_(student_details.user_id.cast(Integer) > (staff.advisor_class*10000), student_details.user_id.cast(Integer) < ((staff.advisor_class+1)*10000) )).all()
                student_dict = {}
                student_list = []
                for student in students:
                    print(student.user_id)
                    courses = db.session.query(course.course_code, course.course_name).join(student_enrolled, student_enrolled.course_code == course.course_code).filter(student_enrolled.user_id == student.user_id)
                    for i in courses:
                        course_dict = {}
                        course_list = []
                        total_hours_query = db.session.query(db.func.sum(attendance.class_hour)).filter_by(course_code= i.course_code,user_id=student.user_id).first()
                        present_hours_query = db.session.query(db.func.sum(attendance.class_hour)).filter_by(status=True,course_code=i.course_code,user_id=student.user_id).first()
                        present_hours = present_hours_query[0] if present_hours_query[0] is not None else 0
                        total_hours = total_hours_query[0] if total_hours_query[0] is not None else 0
                        percentage = (present_hours/total_hours *100) if total_hours != 0 else 0
                        course_dict= {"course_code": i.course_code, "course_name": i.course_name, "percentage": percentage}
                        print(course_dict)
                        course_list.append(course_dict)
                        print(course_list)
                    student_dict = {"student": student.user_id, "attendance": course_list}
                    student_list.append(student_dict)
                return student_list
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500


# -------------------------------------------------------------------------------------------------------------------- #


class FacultyEnrollment(Resource):
    @jwt_required()
    @marshal_with(course_fields)
    def post(self,user_id):     # to store courses enrolled by faculty
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_teacher']:
                args = enroll_post.parse_args()
                is_course = course.query.filter_by(course_code=args["course_code"]).first()
                has_teacher_enrolled = teacher_assigned.query.filter_by(user_id=user_id,course_code=args["course_code"]).first()
                if not is_course:
                    abort(404,  message="Could not find such course")
                elif has_teacher_enrolled:
                    abort(404, message= "You have already enrolled to this subject")
                add_enrollment = teacher_assigned(user_id = user_id,course_code=args["course_code"])
                db.session.add(add_enrollment)
                db.session.commit()
                return "Enrollment successful... ",201
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500


class ViewFacultyEnrolled(Resource):
    @jwt_required()
    def get(self,user_id):      # to view courses enrolled by a particular faculty for list classes
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_teacher']:
                enrolled_courses = db.session.query(course.course_code, course.course_name).join(teacher_assigned, course.course_code == teacher_assigned.course_code).filter(teacher_assigned.user_id == user_id)
                faculty_courses = {}
                course_list = []
                for i in enrolled_courses:
                    faculty_courses = {"course_code": i.course_code, "course_name": i.course_name}
                    course_list.append(faculty_courses)
                if not enrolled_courses:
                    abort(404, message="Faculty haven't assigned to any course")
                return course_list
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500


class TakeAttendance(Resource):
    @jwt_required()
    def get(self,course_code):      # display student list in take attendance page
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_teacher']:
                students = db.session.query(student_enrolled.user_id, student_details.user_name).join(student_details, student_enrolled.user_id == student_details.user_id).filter(student_enrolled.course_code == course_code)
                if not students:
                    abort(404, message = "no student enrolled for the course")
                student_dict = {}
                student_list = []
                ab_date = date.today()
                absentees = db.session.query( absence_intimation.user_id, absence_intimation.status).filter(and_(absence_intimation.course_code == course_code, absence_intimation.absent_date == ab_date))
                att_status = 0
                for i in students:
                    for j in absentees:
                        if i.user_id == j.user_id and j.status == 1:
                            att_status = 1
                    student_dict = {"user_id": i.user_id, "user_name": i.user_name, "att_status": att_status}
                    student_list.append(student_dict)
                return student_list
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500

    
    @jwt_required()
    def post(self,course_code):     # to store attendance taken of a class of n students in db
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_teacher']:
                json_dict = request.data
                dict_att = json.loads(json_dict)
                for i in dict_att:
                    del i["user_name"]
                    att = attendance(**i)
                    db.session.add(att)
                    db.session.commit()
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500

class OverallAttendanceforCourse(Resource):
    @jwt_required()
    def get(self,course_code):      # display overall attendance of each student in a particular course
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_teacher']:
                students = db.session.query(student_enrolled.user_id, student_details.user_name).join(student_details, student_enrolled.user_id == student_details.user_id).filter(student_enrolled.course_code == course_code)
                student_dict = {}
                student_list=[]
                for i in students:
                    present_hours_query = db.session.query(db.func.sum(attendance.class_hour)).filter_by(status=True,course_code=course_code,user_id=i.user_id).first()
                    total_hours_query = db.session.query(db.func.sum(attendance.class_hour)).filter_by(course_code=course_code,user_id=i.user_id).first()
                    present_hours = present_hours_query[0] if present_hours_query[0] is not None else 0
                    total_hours = total_hours_query[0] if total_hours_query[0] is not None else 0
                    percentage =  (present_hours/total_hours*100) if total_hours != 0 else 0
                    student_dict= {"user_id": i.user_id, "user_name": i.user_name, "present_hours": present_hours, "total_class_hours": total_hours, "percentage":percentage}
                    student_list.append(student_dict)
                if not students:
                    abort(404, message = "something went wrong")
                return student_list
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500


class AbsenceListFaculty(Resource): 
    @jwt_required()
    def get(self,user_id):  # to display the list of forms initimated to a particular faculty
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_teacher']:
                user_id_list = db.session.query(absence_intimation.absent_id, absence_intimation.user_id, absence_intimation.status).join(teacher_assigned, teacher_assigned.course_code==absence_intimation.course_code).filter(teacher_assigned.user_id == user_id)
                if not user_id_list:
                    abort(404, message="No absence intimation forms found")
                absentees_dict = {}
                absentees_list = []
                for i in user_id_list:
                    user_name_list = student_details.query.filter_by(user_id=i.user_id).first()
                    absentees_dict = {"absent_id":i.absent_id, "user_name": user_name_list.user_name, "user_id": i.user_id, "status":i.status}
                    absentees_list.append(absentees_dict)
                return absentees_list
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500


class ViewFormFaculty(Resource):
    @jwt_required()
    def get(self,absent_id):    # to view the form the faculty clicks on
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_teacher']:
                absence_details = absence_intimation.query.filter_by(absent_id=absent_id)
                if not absence_details:
                    abort(404, message="No details found for the form")
                user_list = student_details.query.filter_by(user_id=absence_details[0].user_id).first()
                details_dict = {}
                details_dict= {"user_id":absence_details[0].user_id, "email_id":user_list.email_id, "course_code": absence_details[0].course_code, "absent_date":str(absence_details[0].absent_date),"absent_hour": absence_details[0].absent_hour,"absent_reason": absence_details[0].absent_reason }
                return details_dict
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500

    
class UpdateStatus(Resource):
    @jwt_required()
    @marshal_with(up_status)
    def post(self,absent_id):     # to update the respond provided by the faculty in a form
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_teacher']:
                args = update_status.parse_args()
                is_form = absence_intimation.query.filter_by(absent_id =absent_id).first()
                if not is_form:
                    abort(404, message="Could not find such a form")
                # absence_intimation.query.filter_by(absent_id=absent_id).update({"status": args["status"]})
                is_form.status = args["status"]
                db.session.commit()
                return args, 201
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500


class DailyAttendanceFaculty(Resource):
    @jwt_required()
    @marshal_with(daily_att_fields)
    def post(self):     # to display the daily attendance for a particular course by a faculty given range of date
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_teacher']:
                args = daily_att.parse_args()
                first_day_class = attendance.query.order_by(attendance.class_date).filter(attendance.course_code == args["course_code"]).first()
                last_day_class = attendance.query.order_by(attendance.class_date.desc()).filter(attendance.course_code == args["course_code"]).first()
                if not first_day_class or not last_day_class:
                    abort(409, message="You haven't took class")
                if args["to_date"] >= date.today():
                    args["to_date"] = last_day_class
                elif args["from_date"] <= first_day_class:
                    args["from_date"] = first_day_class
                students = db.session.query(student_enrolled.user_id, student_details.user_name).join(student_details, student_enrolled.user_id == student_details.user_id).filter(student_enrolled.course_code == args["course_code"])
                att_dict = {}
                att_list = []
                result_dict = {}
                for student in students:
                    key = [{"user_id": student.user_id, "user_name": student.user_name}]
                    att = attendance.query.filter(and_(attendance.class_date >= args["from_date"], attendance.class_date <= args["to_date"], attendance.course_code == args["course_code"], attendance.user_id == student.user_id))
                    for i in att:
                        att_dict = {"class_date": i.class_date, "class_hour": i.class_hour, "status": i.status}
                        att_list.append(att_dict)
                    value = att_list
                    result_dict[key] = value
                return result_dict
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500



# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   #
    

class OverallAttendanceforStudent(Resource):
    @jwt_required()
    def get(self,user_id):      # display overall attendance of a student in each course
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_student']:
                courses = db.session.query(course.course_code, course.course_name).join(student_enrolled, student_enrolled.course_code == course.course_code).filter(student_enrolled.user_id == user_id)
                student_dict = {}
                course_list=[]
                for i in courses:
                    total_hours_query = db.session.query(db.func.sum(attendance.class_hour)).filter_by(course_code= i.course_code,user_id=user_id).first()
                    present_hours_query = db.session.query(db.func.sum(attendance.class_hour)).filter_by(status=True,course_code=i.course_code,user_id=user_id).first()
                    present_hours = present_hours_query[0] if present_hours_query[0] is not None else 0
                    total_hours = total_hours_query[0] if total_hours_query[0] is not None else 0
                    percentage =  (present_hours/total_hours*100) if total_hours != 0 else 0
                    student_dict= {"course_code": i.course_code, "course_name": i.course_name, 
                                "present_hours": present_hours, "total_hours": total_hours, "percentage": percentage}
                    course_list.append(student_dict)
                if not courses:
                    abort(404, message = "something went wrong")
                return course_list
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500


class ViewStudentEnrolled(Resource):
    @jwt_required()
    def get(self,user_id):
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_student']:
                courses = db.session.query(course.course_code, course.course_name).join(student_enrolled, student_enrolled.course_code == course.course_code).filter(student_enrolled.user_id == user_id)
                course_list = []
                if not courses:
                    abort(404, message="no course enrolled by this student")
                for i in courses:
                    course_str = i.course_code + " - " + i.course_name
                    course_list.append(course_str)
                return course_list
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500

    
class TakeForm(Resource): 
    @jwt_required()
    @marshal_with(absent_fields)
    def post(self):     #take form
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_student']:
                args = absent_post.parse_args()
                is_intimated = absence_intimation.query.filter_by(user_id=args["user_id"],course_code=args["course_code"],absent_date=args['absent_date']).first()
                dt = datetime.now()
                if is_intimated:
                    abort(404, message="Already the absence form for this date and course is intimated!!")
                args = absent_post.parse_args()
                add_absence = absence_intimation(user_id = args["user_id"],course_code=args["course_code"],absent_date=args['absent_date'],absent_hour=args['absent_hour'],absent_reason=args['absent_reason'])
                db.session.add(add_absence)
                db.session.commit()
                return args, 201
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500


class AbsenceListStudent(Resource): 
    @jwt_required()
    def get(self,user_id):  # to display the list of forms initimated by a particular student
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_student']:
                forms = db.session.query(absence_intimation.created_at,absence_intimation.absent_id, absence_intimation.course_code, absence_intimation.status).filter(absence_intimation.user_id == user_id)
                if not forms:
                    abort(404, message="No absence intimation forms found")
                form_dict = {}
                form_list = []
                for i in forms:
                    course_detail = course.query.filter_by(course_code = i.course_code).first()
                    form_dict = {"absent_id":i.absent_id, "course_name": course_detail.course_name, "status":i.status, "date":i.created_at}
                    form_list.append(form_dict)
                return form_list
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500


class ViewFormStudent(Resource):
    @jwt_required()
    def get(self,absent_id):    # to view the form the student clicks on
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_student']:
                absence_details = absence_intimation.query.filter_by(absent_id=absent_id)
                if not absence_details:
                    abort(404, message="No details found for the form")
                details_dict = {}
                details_dict= {"course_code": absence_details[0].course_code, "absent_date":str(absence_details[0].absent_date),"absent_hour": absence_details[0].absent_hour,"absent_reason": absence_details[0].absent_reason,"absent_status": absence_details[0].status }
                return details_dict
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500

    
class DailyAttendanceStudent(Resource):
    @jwt_required()
    @marshal_with(daily_att_fields)
    def post(self,user_id):
        response = requests.get('http://localhost:5000/protected')
        
        if response.status_code == 200:
            data = response.json()
            if data['allowed_to_student']:
                args = daily_att.parse_args()
                courses = db.session.query(course.course_code,course.course_name).join(student_enrolled, student_enrolled.course_code == course.course_code).filter(student_enrolled.user_id == user_id)
                att_dict = {}
                att_list = []
                result_dict = {}
                result_list = []
                if not courses:
                    abort(404, message="no course enrolled by this student")
                for i in courses:
                    first_day_class = attendance.query.order_by(attendance.class_date).filter(attendance.course_code == i.course_code).first()
                    last_day_class = attendance.query.order_by(attendance.class_date.desc()).filter(attendance.course_code == i.course_code).first()
                    from_date = datetime.strptime(args["from_date"], '%d-%m-%y').date()
                    to_date = datetime.strptime(args["to_date"], '%d-%m-%y').date()
                    if not first_day_class or not last_day_class:
                        abort(409, message="You haven't took class")
                    if to_date > last_day_class.class_date:
                        to_date = last_day_class.class_date
                    elif from_date < first_day_class.class_date:
                        from_date = first_day_class.class_date
                    key = i.course_code + ' ' + i.course_name
                    att = attendance.query.filter(and_(attendance.class_date >= from_date, attendance.class_date <= to_date, attendance.course_code == i.course_code, attendance.user_id == user_id))
                    for i in att:
                        att_dict = {"class_date": str(i.class_date), "class_hour": i.class_hour, "status": i.status}
                        att_list.append(att_dict)
                    value = att_list
                    result_dict[key] = value
                    result_list.append(result_dict)
                    print(result_list)
                return result_list
            else:
                return {'message': 'Access denied. User does not have permission to access this functionality.'}, 403
        else:
            return {'message': 'Error while checking permissions'}, 500


# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- #

class Logout(Resource):
    @jwt_required()
    def post(self):
        unset_jwt_cookies()
        return redirect(url_for('UserLogin'))

api.add_resource(ProtectedResource, '/protected')
api.add_resource(UserRegister,'/UserRegister')
api.add_resource(UserLogin,'/UserLogin')
api.add_resource(SendOTPFgtPwd,'/SendOTPFgtPwd')
api.add_resource(UpdatePassword,'/UpdatePassword')
api.add_resource(CourseRegister,'/CourseRegister')
api.add_resource(CoursesInSem,'/CoursesInSem/<int:semester_in>')
api.add_resource(MyStudentList,'/MyStudentList/<string:user_id>')
api.add_resource(MyStudentEnrollment,'/MyStudentEnrollment')
api.add_resource(OverallAttendanceforAdvisor,'/OverallAttendanceforAdvisor/<string:user_id>')
api.add_resource(FacultyEnrollment,'/FacultyEnrollment/<string:user_id>')
api.add_resource(ViewFacultyEnrolled,'/ViewFacultyEnrolled/<string:user_id>')
api.add_resource(TakeAttendance,'/TakeAttendance/<string:course_code>')
api.add_resource(OverallAttendanceforCourse,'/OverallAttendanceforCourse/<string:course_code>')
api.add_resource(AbsenceListFaculty,'/AbsenceListFaculty/<string:user_id>')
api.add_resource(ViewFormFaculty,'/ViewFormFaculty/<int:absent_id>')
api.add_resource(UpdateStatus,'/UpdateStatus/<int:absent_id>')
api.add_resource(DailyAttendanceFaculty,'/DailyAttendanceFaculty')
api.add_resource(OverallAttendanceforStudent,'/OverallAttendanceforStudent/<string:user_id>')
api.add_resource(ViewStudentEnrolled,'/ViewStudentEnrolled/<string:user_id>')
api.add_resource(TakeForm,'/TakeForm')
api.add_resource(AbsenceListStudent,'/AbsenceListStudent/<string:user_id>')
api.add_resource(ViewFormStudent,'/ViewFormStudent/<int:absent_id>')
api.add_resource(DailyAttendanceStudent,'/DailyAttendanceStudent/<string:user_id>')
api.add_resource(Logout,'/Logout')

if __name__ == '__main__':
   app.run(debug=True)
