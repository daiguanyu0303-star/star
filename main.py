from flask import Flask, request, jsonify, send_from_directory, abort
from flask_jwt_extended import (JWTManager, create_access_token, jwt_required,
                                get_jwt)
from flask_cors import CORS
from dotenv import load_dotenv
from replit import db as replit_db
from PIL import Image
import os
import uuid
import datetime
import logging
import bcrypt
import re
import json
from werkzeug.exceptions import RequestEntityTooLarge

# -------------------------- 基础配置（加点注释） --------------------------
app = Flask(__name__)
CORS(app)
load_dotenv()

# 日志配置
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)

# 文件上传配置（核心优化：头像大小限制2MB）
MAX_AVATAR_SIZE = 2 * 1024 * 1024  # 2MB
app.config['MAX_CONTENT_LENGTH'] = MAX_AVATAR_SIZE
# 支持的头像格式（扩展webp）
ALLOWED_AVATAR_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# JWT 配置
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY',
                                         'your-secret-key-keep-it-safe')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
jwt = JWTManager(app)

# 文件存储配置
UPLOAD_FOLDER = 'uploads/avatars'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# -------------------------- 工具函数 --------------------------
def allowed_avatar_file(filename):
    """严格校验头像文件格式"""
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_AVATAR_EXTENSIONS


def hash_password(password):
    """密码加密"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(plain_password, hashed_password):
    """验证密码"""
    return bcrypt.checkpw(plain_password.encode('utf-8'),
                          hashed_password.encode('utf-8'))


def init_admin():
    """初始化管理员"""
    if 'admin' not in replit_db:
        hashed_pwd = hash_password('admin123')
        replit_db['admin'] = {
            'username': 'admin',
            'password': hashed_pwd,
            'role': 'admin',
            'created_at': str(datetime.datetime.now())
        }
    if 'employees' not in replit_db:
        replit_db['employees'] = []


def delete_avatar_file(avatar_url):
    """删除头像文件（工具函数）"""
    if not avatar_url:
        return
    try:
        filepath = avatar_url.lstrip('/')
        if os.path.exists(filepath):
            os.remove(filepath)
            logger.info(f"头像文件已删除：{filepath}")
    except Exception as e:
        logger.error(f"删除头像文件失败：{str(e)}")


# -------------------------- 健康检查接口（新增） --------------------------
@app.route('/')
def health_check():
    """根路径健康检查，用于 Replit 部署验证"""
    return jsonify({
        'success': True,
        'message': '员工管理系统运行正常',
        'status': 'healthy'
    }), 200


# -------------------------- 全局错误处理 --------------------------
@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(error):
    """文件过大错误处理（针对性提示）"""
    return jsonify({
        'success': False,
        'code': 413,
        'message': f'头像文件大小超过限制（最大{MAX_AVATAR_SIZE//1024}KB）'
    }), 413, {
        'Content-Type': 'application/json; charset=utf-8'
    }


@app.errorhandler(Exception)
def handle_generic_error(error):
    """全局异常处理"""
    logger.error(f"系统错误: {str(error)}")
    return jsonify({
        'success': False,
        'code': 500,
        'message': '服务器内部错误，请稍后重试'
    }), 500, {
        'Content-Type': 'application/json; charset=utf-8'
    }


# -------------------------- API 接口 --------------------------
# 1. 登录接口
@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({
                'success': False,
                'code': 400,
                'message': '用户名和密码不能为空'
            }), 400, {
                'Content-Type': 'application/json; charset=utf-8'
            }

        admin = replit_db.get('admin')
        if not admin:
            return jsonify({
                'success': False,
                'code': 401,
                'message': '管理员账户未初始化'
            }), 401, {
                'Content-Type': 'application/json; charset=utf-8'
            }

        if username == admin['username'] and verify_password(
                password, admin['password']):
            access_token = create_access_token(
                identity=username, additional_claims={"role": admin['role']})
            logger.info(f"管理员 {username} 登录成功")
            return jsonify({
                'success': True,
                'access_token': access_token,
                'role': admin['role']
            }), 200, {
                'Content-Type': 'application/json; charset=utf-8'
            }
        else:
            logger.warning(f"管理员登录失败：用户名或密码错误")
            return jsonify({
                'success': False,
                'code': 401,
                'message': '用户名或密码错误'
            }), 401, {
                'Content-Type': 'application/json; charset=utf-8'
            }
    except Exception as e:
        logger.error(f"登录接口错误: {str(e)}")
        raise


# 2. 新增员工（头像上传优化）
@app.route('/api/employees', methods=['POST'])
@jwt_required()
def add_employee():
    try:
        jwt_claims = get_jwt()
        if jwt_claims.get('role') != 'admin':
            return jsonify({
                'success': False,
                'code': 403,
                'message': '无操作权限'
            }), 403, {
                'Content-Type': 'application/json; charset=utf-8'
            }

        data = request.form
        required_fields = ['name', 'department', 'position', 'phone']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'code': 400,
                    'message': f'{field} 不能为空'
                }), 400, {
                    'Content-Type': 'application/json; charset=utf-8'
                }

        employee_id = str(uuid.uuid4())
        avatar_url = None

        # 头像上传处理（核心优化）
        if 'avatar' in request.files:
            file = request.files['avatar']
            # 空文件校验
            if file.filename == '':
                return jsonify({
                    'success': False,
                    'code': 400,
                    'message': '请选择要上传的头像文件'
                }), 400, {
                    'Content-Type': 'application/json; charset=utf-8'
                }

            # 格式校验
            if not allowed_avatar_file(file.filename):
                return jsonify({
                    'success':
                    False,
                    'code':
                    400,
                    'message':
                    f'头像格式不支持，仅允许：{", ".join(ALLOWED_AVATAR_EXTENSIONS)}'
                }), 400, {
                    'Content-Type': 'application/json; charset=utf-8'
                }

            # 大小校验（二次防护）
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)
            if file_size > MAX_AVATAR_SIZE:
                return jsonify({
                    'success':
                    False,
                    'code':
                    400,
                    'message':
                    f'头像文件大小超过限制（最大{MAX_AVATAR_SIZE//1024}KB）'
                }), 400, {
                    'Content-Type': 'application/json; charset=utf-8'
                }

            # 处理图片
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = f"{employee_id}_{uuid.uuid4()}.{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # 压缩图片（固定200x200，保持比例）
            try:
                img = Image.open(file)
                img.thumbnail((200, 200), Image.Resampling.LANCZOS)
                img.save(filepath)
                avatar_url = f"/uploads/avatars/{filename}"
                logger.info(f"头像上传成功：{filename}（大小：{file_size//1024}KB）")
            except Exception as e:
                # 上传失败清理文件
                if os.path.exists(filepath):
                    os.remove(filepath)
                return jsonify({
                    'success': False,
                    'code': 400,
                    'message': f'头像处理失败：{str(e)}'
                }), 400, {
                    'Content-Type': 'application/json; charset=utf-8'
                }

        # 构建员工信息
        new_employee = {
            'id': employee_id,
            'name': data.get('name'),
            'department': data.get('department'),
            'position': data.get('position'),
            'phone': data.get('phone'),
            'avatar_url': avatar_url,
            'created_at': str(datetime.datetime.now()),
            'updated_at': str(datetime.datetime.now())
        }

        # 保存到数据库
        employees = list(replit_db['employees'])
        employees.append(new_employee)
        replit_db['employees'] = employees

        logger.info(f"新增员工成功：{new_employee['name']}（ID：{employee_id}）")
        return jsonify({
            'success': True,
            'code': 201,
            'employee': new_employee
        }), 201, {
            'Content-Type': 'application/json; charset=utf-8'
        }
    except Exception as e:
        logger.error(f"新增员工错误: {str(e)}")
        raise


# 3. 编辑员工（新增头像删除功能）
@app.route('/api/employees/<employee_id>', methods=['PUT'])
@jwt_required()
def update_employee(employee_id):
    try:
        jwt_claims = get_jwt()
        if jwt_claims.get('role') != 'admin':
            return jsonify({
                'success': False,
                'code': 403,
                'message': '无操作权限'
            }), 403, {
                'Content-Type': 'application/json; charset=utf-8'
            }

        data = request.form
        employees = [dict(emp) for emp in list(replit_db['employees'])]
        employee_index = -1

        # 查找员工
        for i, emp in enumerate(employees):
            if emp['id'] == employee_id:
                employee_index = i
                break

        if employee_index == -1:
            return jsonify({
                'success': False,
                'code': 404,
                'message': '员工不存在'
            }), 404, {
                'Content-Type': 'application/json; charset=utf-8'
            }

        updated_employee = employees[employee_index]

        # 更新基础信息
        if data.get('name'):
            updated_employee['name'] = data.get('name')
        if data.get('department'):
            updated_employee['department'] = data.get('department')
        if data.get('position'):
            updated_employee['position'] = data.get('position')
        if data.get('phone'):
            updated_employee['phone'] = data.get('phone')
        updated_employee['updated_at'] = str(datetime.datetime.now())

        # 核心优化1：主动删除头像（传 delete_avatar=1 即可）
        if data.get('delete_avatar') == '1':
            delete_avatar_file(updated_employee.get('avatar_url'))
            updated_employee['avatar_url'] = None
            logger.info(f"员工 {employee_id} 头像已主动删除")

        # 核心优化2：替换头像（先删旧的，再传新的）
        elif 'avatar' in request.files:
            file = request.files['avatar']
            # 空文件校验
            if file.filename == '':
                return jsonify({
                    'success': False,
                    'code': 400,
                    'message': '请选择要上传的头像文件'
                }), 400, {
                    'Content-Type': 'application/json; charset=utf-8'
                }

            # 格式校验
            if not allowed_avatar_file(file.filename):
                return jsonify({
                    'success':
                    False,
                    'code':
                    400,
                    'message':
                    f'头像格式不支持，仅允许：{", ".join(ALLOWED_AVATAR_EXTENSIONS)}'
                }), 400, {
                    'Content-Type': 'application/json; charset=utf-8'
                }

            # 大小校验
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)
            if file_size > MAX_AVATAR_SIZE:
                return jsonify({
                    'success':
                    False,
                    'code':
                    400,
                    'message':
                    f'头像文件大小超过限制（最大{MAX_AVATAR_SIZE//1024}KB）'
                }), 400, {
                    'Content-Type': 'application/json; charset=utf-8'
                }

            # 删除旧头像
            delete_avatar_file(updated_employee.get('avatar_url'))

            # 上传新头像
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = f"{employee_id}_{uuid.uuid4()}.{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                img = Image.open(file)
                img.thumbnail((200, 200), Image.Resampling.LANCZOS)
                img.save(filepath)
                updated_employee['avatar_url'] = f"/uploads/avatars/{filename}"
                logger.info(f"员工 {employee_id} 头像替换成功：{filename}")
            except Exception as e:
                if os.path.exists(filepath):
                    os.remove(filepath)
                return jsonify({
                    'success': False,
                    'code': 400,
                    'message': f'头像处理失败：{str(e)}'
                }), 400, {
                    'Content-Type': 'application/json; charset=utf-8'
                }

        # 保存更新
        employees[employee_index] = updated_employee
        replit_db['employees'] = employees

        logger.info(f"编辑员工成功：{updated_employee['name']}（ID：{employee_id}）")
        return jsonify({
            'success': True,
            'code': 200,
            'employee': updated_employee
        }), 200, {
            'Content-Type': 'application/json; charset=utf-8'
        }
    except Exception as e:
        logger.error(f"编辑员工错误: {str(e)}")
        raise


# 4. 员工查询（支持Unicode筛选）
@app.route('/api/employees', methods=['GET'])
@jwt_required()
def get_employees():
    try:
        jwt_claims = get_jwt()
        if jwt_claims.get('role') != 'admin':
            return jsonify({
                'success': False,
                'code': 403,
                'message': '无操作权限'
            }), 403, {
                'Content-Type': 'application/json; charset=utf-8'
            }

        page = int(request.args.get('page', 1))
        size = int(request.args.get('size', 10))
        department = request.args.get('department', '').strip()
        name = request.args.get('name', '').strip()

        employees = list(replit_db['employees'])
        employees = [dict(emp) for emp in employees]

        # 直接匹配Unicode字符串
        filtered_employees = employees
        if department:
            filtered_employees = [
                emp for emp in filtered_employees
                if department in str(emp['department'])
            ]
        if name:
            filtered_employees = [
                emp for emp in filtered_employees if name in str(emp['name'])
            ]

        total = len(filtered_employees)
        max_page = max(1, (total + size - 1) // size)
        page = max(1, min(page, max_page))

        start = (page - 1) * size
        end = start + size
        paginated_employees = filtered_employees[start:end]

        logger.info(f"查询员工成功：共{total}条，当前第{page}页，每页{size}条")
        return jsonify({
            'success': True,
            'code': 200,
            'data': {
                'employees': paginated_employees,
                'pagination': {
                    'total': total,
                    'page': page,
                    'size': size,
                    'pages': max_page
                }
            },
            'message': '查询成功'
        }), 200, {
            'Content-Type': 'application/json; charset=utf-8'
        }
    except Exception as e:
        logger.error(f"查询员工错误: {str(e)}")
        raise


# 5. 删除员工（同步删除头像）
@app.route('/api/employees/<employee_id>', methods=['DELETE'])
@jwt_required()
def delete_employee(employee_id):
    try:
        jwt_claims = get_jwt()
        if jwt_claims.get('role') != 'admin':
            return jsonify({
                'success': False,
                'code': 403,
                'message': '无操作权限'
            }), 403, {
                'Content-Type': 'application/json; charset=utf-8'
            }

        employees = [dict(emp) for emp in list(replit_db['employees'])]
        employee_index = -1

        for i, emp in enumerate(employees):
            if emp['id'] == employee_id:
                employee_index = i
                break

        if employee_index == -1:
            return jsonify({
                'success': False,
                'code': 404,
                'message': '员工不存在'
            }), 404, {
                'Content-Type': 'application/json; charset=utf-8'
            }

        # 删除头像文件
        deleted_employee = employees[employee_index]
        delete_avatar_file(deleted_employee.get('avatar_url'))

        # 删除员工
        del employees[employee_index]
        replit_db['employees'] = employees

        logger.info(f"删除员工成功：ID：{employee_id}")
        return jsonify({
            'success': True,
            'code': 200,
            'message': '员工已删除'
        }), 200, {
            'Content-Type': 'application/json; charset=utf-8'
        }
    except Exception as e:
        logger.error(f"删除员工错误: {str(e)}")
        raise


# 6. 新增：头像预览接口（按员工ID）
@app.route('/api/employees/<employee_id>/avatar', methods=['GET'])
@jwt_required()
def preview_avatar(employee_id):
    """员工头像预览接口（直接返回图片）"""
    try:
        jwt_claims = get_jwt()
        if jwt_claims.get('role') != 'admin':
            abort(403)

        employees = [dict(emp) for emp in list(replit_db['employees'])]
        for emp in employees:
            if emp['id'] == employee_id:
                avatar_url = emp.get('avatar_url')
                if not avatar_url:
                    abort(404, description="该员工未上传头像")

                filename = avatar_url.split('/')[-1]
                return send_from_directory(app.config['UPLOAD_FOLDER'],
                                           filename)

        abort(404, description="员工不存在")
    except Exception as e:
        logger.error(f"头像预览错误: {str(e)}")
        abort(500)


# 7. 静态文件访问
@app.route('/uploads/avatars/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# -------------------------- 启动应用 --------------------------
if __name__ == '__main__':
    init_admin()
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
