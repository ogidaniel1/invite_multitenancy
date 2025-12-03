from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from sqlalchemy import and_, or_
from sqlalchemy.orm import joinedload
from functools import wraps
import json
from flask_wtf.csrf import generate_csrf, validate_csrf,CSRFError
from flask import current_app
from app.models import db,Location,Event,Admin,Organization,Admin,Invitation,Invitee
from app.models import InviteeForm,super_required,SubmitField,Feedback,readable_role_label
from app import csrf,mail
from app.models import FeedbackForm,AttendanceForm,AdminForm,admin_or_super_required
import secrets
from werkzeug.security import generate_password_hash

# Assuming you have these models - adjust imports based on your project structure
# from app import db, Admin, Organization, Location, Invitation
from app.inv.tokens import send_invitee_invitation_email,send_admin_invite_email,send_invitation_email # Assuming you have email utilities


admin_bp = Blueprint('admin', __name__, template_folder='../templates')


def super_admin_required(f):
    """Decorator to ensure only super admins can access certain routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'super_admin':
            flash('Access denied. Super admin privileges required.', 'error')
            return redirect(url_for('inv.universal_login'))
        return f(*args, **kwargs)
    return decorated_function



# --- Existing management_dashboard and get_organizations routes ---
@admin_bp.route('/admin/management')
# @super_admin_required
@super_required
def management_dashboard():
    """Main management dashboard page"""
    return render_template('management.html')


# API Routes for Organizations
@admin_bp.route('/api/admin/organizations')
# @super_admin_required
@super_required
def get_organizations():
    """Get all organizations"""
    # from app import Organization # Ensure Organization model is imported
    try:
        orgs = Organization.query.order_by(Organization.created_at.desc()).limit(20).all()
        return jsonify([{
            'id': org.id,
            'name': org.name,
            'slug': getattr(org, 'slug', None),
            'is_active': getattr(org, 'is_active', True),
            'created_at': org.created_at.isoformat() if hasattr(org, 'created_at') else None
        } for org in orgs])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# NEW: Create Organization
@admin_bp.route('/api/admin/organizations', methods=['POST'])
@login_required
@super_admin_required
def create_organization():
    """Create a new organization"""
    # from app import db, Organization # Ensure models are imported
    try:
        data = request.get_json()
        name = data.get('name')
        slug = data.get('slug') # Assuming slug is also passed or generated
        is_active = data.get('is_active', True)

        if not name:
            return jsonify({'error': 'Organization name is required.'}), 400
        
        # Optional: Add uniqueness check for name or slug
        if Organization.query.filter_by(name=name).first():
            return jsonify({'error': 'Organization with this name already exists.'}), 409 # Conflict

        new_org = Organization(name=name, slug=slug, is_active=is_active)
        db.session.add(new_org)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Organization created successfully',
            'organization': {
                'id': new_org.id,
                'name': new_org.name,
                'slug': new_org.slug,
                'is_active': new_org.is_active
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# NEW: Update Organization
@admin_bp.route('/api/admin/organizations/<int:org_id>', methods=['PUT', 'PATCH'])
@login_required
@super_admin_required
def update_organization(org_id):
    """Update an existing organization"""
    # from app import db, Organization # Ensure models are imported
    try:
        org = Organization.query.get_or_404(org_id)
        data = request.get_json()

        if 'name' in data:
            org.name = data['name']
        if 'slug' in data:
            org.slug = data['slug']
        if 'is_active' in data:
            org.is_active = data['is_active']
        
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Organization updated successfully',
            'organization': {
                'id': org.id,
                'name': org.name,
                'slug': org.slug,
                'is_active': org.is_active
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# NEW: Delete Organization
@admin_bp.route('/api/admin/organizations/<int:org_id>', methods=['DELETE'])
@login_required
@super_admin_required
def delete_organization(org_id):
    """Delete an organization"""
    # from app import db, Organization # Ensure models are imported
    try:
        org = Organization.query.get_or_404(org_id)
        db.session.delete(org)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Organization deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# API Routes for Locations
@admin_bp.route('/api/admin/locations')
@login_required
@super_admin_required
def get_locations():
    # from app import Organization,Location # Ensure models are imported
    """Get all locations with filtering"""
    try:
        query = Location.query.join(Organization)
        # ... (existing filtering logic) ...
        # Filters
        org_id = request.args.get('organization_id')
        location = request.args.get('location')  # Volunteer, Guest, Attendee
        status = request.args.get('status')  # Present, Absent, Confirmed
        search = request.args.get('search')

        if org_id:
            
            try:
                org_id_int= int(org_id)
                query = query.filter(Location.organization_id == org_id_int)
                current_app.logger.info(f"here we check invalid org id:  {org_id_int}")
            
            except ValueError:
                current_app.logger.warning(f"Invalid org_id passed:  {org_id}")
        
        if location:
            query = query.filter(Location.name == location)
        

        if status == 'active':
            query = query.filter(Location.is_active == True)
        elif status == 'inactive':
            query = query.filter(Location.is_active == False)

        if search:
            search_term = f'%{search}%'
            query = query.filter(
                or_(
                    Location.name.ilike(search_term),
                    Location.address.ilike(search_term)
                )
            )

        locations = query.order_by(Location.created_at.desc()).limit(20).all()
        
        return jsonify([{
            'id': loc.id,
            'name': loc.name,
            'slug': getattr(loc, 'slug', None),
            'address': getattr(loc, 'address', ''),
            'is_active': loc.is_active,
            'organization': {
                'id': loc.organization.id,
                'name': loc.organization.name
            } if loc.organization else None,
            'created_at': loc.created_at.isoformat() if hasattr(loc, 'created_at') else None
        } for loc in locations])
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    


# NEW: Create Location
@admin_bp.route('/api/admin/locations', methods=['POST'])
@login_required
@super_admin_required
def create_location():
    """Create a new location"""
    # from app import db, Location, Organization # Ensure models are imported
    
    try:
        # csrf_token = request.headers.get('X-CSRFToken')
        # validate_csrf(csrf_token)

        data = request.get_json()
        name = data.get('name')
        address = data.get('address')
        organization_id = data.get('organization_id')
        is_active = data.get('is_active', True)

        if not name or not address or not organization_id:
            return jsonify({'error': 'Name, address, and organization ID are required.'}), 400
        
        organization = Organization.query.get(organization_id)
        if not organization:
            return jsonify({'error': 'Organization not found.'}), 404

        new_loc = Location(name=name, address=address, organization_id=organization_id, is_active=is_active)
        db.session.add(new_loc)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Location created successfully',
            'location': {
                'id': new_loc.id,
                'name': new_loc.name,
                'address': new_loc.address,
                'is_active': new_loc.is_active,
                'organization_id': new_loc.organization_id
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# NEW: Update Location
@admin_bp.route('/api/admin/locations/<int:location_id>', methods=['PUT', 'PATCH'])
@login_required
@super_admin_required
def update_location(location_id):
    """Update an existing location"""
    # from app import db, Location, Organization # Ensure models are imported
    try:
        location = Location.query.get_or_404(location_id)
        data = request.get_json()

        if 'name' in data:
            location.name = data['name']
        if 'address' in data:
            location.address = data['address']
        if 'is_active' in data:
            location.is_active = data['is_active']
        if 'organization_id' in data:
            organization = Organization.query.get(data['organization_id'])
            if not organization:
                return jsonify({'error': 'Organization not found.'}), 404
            location.organization_id = data['organization_id']
        
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Location updated successfully',
            'location': {
                'id': location.id,
                'name': location.name,
                'address': location.address,
                'is_active': location.is_active,
                'organization_id': location.organization_id
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/locations/<int:location_id>/toggle-status', methods=['POST'])
@login_required
@super_admin_required
def toggle_location_status(location_id):
    # from app import Organization,Location,db
    """Toggle location active status"""
    try:
        location = Location.query.get_or_404(location_id)
        location.is_active = not location.is_active
        db.session.commit()
        
        return jsonify({
            'success': True,
            'is_active': location.is_active,
            'message': f'Location {"activated" if location.is_active else "deactivated"} successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# NEW: Delete Location
@admin_bp.route('/api/admin/locations/<int:location_id>', methods=['DELETE'])
@login_required
@super_admin_required
def delete_location(location_id):
    """Delete a location"""
    # from app import db, Location # Ensure models are imported
    try:
        location = Location.query.get_or_404(location_id)
        db.session.delete(location)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Location deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/locations/bulk-action', methods=['POST','DELETE'])
@login_required
@super_admin_required
def bulk_location_action():
    # from app import Organization,Location,db
    """Perform bulk actions on locations"""
    # ... (existing bulk_location_action logic) ...
    deleted_ids = []
    skipped = []

    try:
        data = request.get_json()
        action = data.get('action')
        location_ids = data.get('location_ids', [])
        
        if not location_ids:
            return jsonify({'error': 'No locations selected'}), 400
        
        locations = Location.query.filter(Location.id.in_(location_ids)).all()
        
        if action == 'activate':
            for loc in locations:
                if loc.is_active:
                    skipped.append({"id":loc.id, "reason":"location is already activated"})
                    continue
                loc.is_active = True

        elif action == 'deactivate':
            for loc in locations:
                if not loc.is_active:
                    skipped.append({"id":loc.id, "reason":"location is already deactivated"})
                    continue
                loc.is_active = False

        elif action == 'delete':
            for loc in locations:
                if loc.is_active:
                    skipped.append({"id": loc.id, "reason": "Cannot delete active location"})
                else:
                    db.session.delete(loc)
                    deleted_ids.append(loc.id)
        else:
            return jsonify({'error': 'Invalid action'}), 400
        
        db.session.commit()
        
        
        return jsonify({
            'success': True,
            'message': f'Bulk {action} completed for {len(locations)} locations',
            'deleted': deleted_ids,
            'skipped': skipped
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



# API Routes for Administrators
@admin_bp.route('/api/admin/administrators') 
@login_required
@super_admin_required
def get_administrators():
    # from app import Organization,Location,db,Admin # Ensure models are imported
    """Get all administrators with filtering"""
    # ... (existing get_administrators logic) ...
    try:
        #'super_admin' removing super admin
        query = Admin.query.filter(Admin.role.in_(['org_admin', 'location_admin']))        
        # Apply filters
        org_id = request.args.get('organization_id')
        role = request.args.get('role')
        status = request.args.get('status')
        search = request.args.get('search')
        
        if org_id:
            try:
                org_id_int= int(org_id)
                query = query.filter(Admin.organization_id == org_id_int)
                current_app.logger.info(f"here we check invalid org id:  {org_id_int}")
            except ValueError:
                current_app.logger.warning(f"Invalid org_id passed:  {org_id}")

        if role:
            query = query.filter(Admin.role == role)
        
        if status == 'active':
            query = query.filter(Admin.is_active == True)
        elif status == 'inactive':
            query = query.filter(Admin.is_active == False)
        
        if search:
            search_term = f'%{search}%'
            query = query.filter(
                or_(
                    Admin.name.ilike(search_term),
                    Admin.email.ilike(search_term)
                )
            )

        admins = query.order_by(Admin.created_at.desc()).limit(20).all()
        return jsonify([{
            'id': admin.id,
            'name': admin.name,
            'email': admin.email,
            'role': admin.role,
            'is_active': admin.is_active,
            'organization': {
                'id': admin.organization.id,
                'name': admin.organization.name
            } if admin.organization else None,
            'last_login': admin.last_login.isoformat() if hasattr(admin, 'last_login') and admin.last_login else None,
            'created_at': admin.created_at.isoformat() if hasattr(admin, 'created_at') else None
        } for admin in admins])
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

# NEW: Create Administrator
@admin_bp.route('/api/admin/administrators', methods=['POST'])
@login_required
@super_admin_required
def create_administrator():
    try:
        data = request.get_json() or {}
        name = (data.get('name') or "").strip()
        email = (data.get('email') or "").strip().lower()
        role = data.get('role')
        organization_id = data.get('organization_id')
        is_active = data.get('is_active', True)

        if not email or not role or organization_id is None:
            return jsonify({'error': 'Email, role, and organization_id are required.'}), 400

        organization = Organization.query.get(organization_id)
        if not organization:
            return jsonify({'error': 'Organization not found.'}), 404

        # ensure uniqueness per organization
        if Admin.query.filter_by(email=email, organization_id=organization_id).first():
            return jsonify({'error': 'Administrator with this email already exists in this organization.'}), 409

        temp_password = secrets.token_urlsafe(8)

        new_admin = Admin(
            name=name or email.split("@")[0],
            email=email,
            role=role,
            organization_id=organization_id,
            is_active=is_active,
            created_at=datetime.utcnow()
        )
        new_admin.set_password(temp_password)

        db.session.add(new_admin)
        db.session.commit()

        # readable role label
        readable_role = readable_role_label(role)

        # send invite (non-blocking recommended)
        email_sent = send_admin_invite_email(
            email=email,
            name=name,
            role=readable_role,
            temp_password=temp_password,
            organization_name=organization.name
        )

        msg = "Administrator created successfully"
        if not email_sent:
            msg += " (email invite may be delayed or failed)"

        return jsonify({
            'success': True,
            'message': msg,
            'admin': {
                'id': new_admin.id,
                'name': new_admin.name,
                'email': new_admin.email,
                'role': readable_role,
                'is_active': new_admin.is_active,
                'temporary_password': temp_password
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Error creating admin")
        return jsonify({'error': str(e)}), 500



# NEW: Update Administrator
@admin_bp.route('/api/admin/administrators/<int:admin_id>', methods=['PUT', 'PATCH'])
@login_required
@super_admin_required
def update_administrator(admin_id):
    try:
        admin = Admin.query.get_or_404(admin_id)
        data = request.get_json() or {}

        # prevent self-demotion/deactivation for super admin
        if admin.id == current_user.id and admin.role == 'super_admin':
            if 'role' in data and data['role'] != 'super_admin':
                return jsonify({'error': 'Cannot change your own super admin role.'}), 400
            if 'is_active' in data and not data['is_active']:
                return jsonify({'error': 'Cannot deactivate your own super admin account.'}), 400

        if 'name' in data:
            admin.name = data['name'].strip()

        if 'email' in data:
            new_email = (data['email'] or '').strip().lower()
            org_id = data.get('organization_id', admin.organization_id)
            
            # uniqueness within organization
            if Admin.query.filter(Admin.email == new_email,
                                  Admin.organization_id == org_id,
                                  Admin.id != admin.id).first():
                return jsonify({'error': 'Email already exists for another administrator in this organization.'}), 409
            admin.email = new_email

        if 'password' in data and data['password']:
            admin.set_password(data['password'])

        if 'role' in data:
            admin.role = data['role']

        if 'is_active' in data:
            admin.is_active = data['is_active']

        if 'organization_id' in data:
            organization = Organization.query.get(data['organization_id'])
            if not organization:
                return jsonify({'error': 'Organization not found.'}), 404
            admin.organization_id = data['organization_id']

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Administrator updated successfully',
            'admin': admin.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Error updating admin")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/administrators/<int:admin_id>/toggle-status', methods=['POST'])
@login_required
@super_admin_required
def toggle_admin_status(admin_id):
    # from app import Admin,db
    """Toggle administrator active status"""
    # ... (existing toggle_admin_status logic) ...
    try:
        admin = Admin.query.get_or_404(admin_id)
        
        # Prevent deactivating the current super admin
        if admin.id == current_user.id and admin.role == 'super_admin':
            return jsonify({'error': 'Cannot deactivate your own super admin account'}), 400
        
        admin.is_active = not admin.is_active
        db.session.commit()
        
        return jsonify({
            'success': True,
            'is_active': admin.is_active,
            'message': f'Administrator {"activated" if admin.is_active else "deactivated"} successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# NEW: Delete Administrator
@admin_bp.route('/api/admin/administrators/<int:admin_id>', methods=['POST'])
@login_required
@super_admin_required
def delete_administrator(admin_id):
    """Delete an administrator"""
    # from app import db, Admin # Ensure models are imported
    is_authorised = True
    try:
        admin = Admin.query.get_or_404(admin_id)

        # Prevent a super_admin from deleting themselves
        if admin.id == current_user.id and admin.role == 'super_admin':
            return jsonify({'error': 'Cannot delete your own super admin account'}), 400


        if admin.is_active and is_authorised:
            return jsonify({'error': 'Cannot delete an active account'}), 400

        db.session.delete(admin)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Administrator deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


#3 in 1 bulk action
@admin_bp.route('/api/admin/administrators/bulk-action', methods=['POST'])
@login_required
@super_admin_required
def bulk_admin_action():
    # from app import Admin,db
    """Perform bulk actions on administrators"""
    # ... (existing bulk_admin_action logic) ...
    deleted_ids = []
    skipped = []

    try:
            data = request.get_json()
            action = data.get('action')
            admin_ids = data.get('admin_ids', [])

            if not admin_ids:
                return jsonify({'error': 'No administrators selected'}), 400

            if current_user.id in admin_ids:
                return jsonify({'error': 'Cannot perform bulk actions on your own account'}), 400

            admins = Admin.query.filter(Admin.id.in_(admin_ids)).all()

            if action == 'activate':
                for admin in admins:
                    if admin.is_active:
                        skipped.append({"id": admin.id, "reason": "Admin is already activated"})
                        continue
                    admin.is_active = True

            elif action == 'deactivate':
                for admin in admins:
                    if not admin.is_active:
                        skipped.append({"id": admin.id, "reason": "Admin is already deactivated"})
                        continue
                    admin.is_active = False

            elif action == 'delete':
                for admin in admins:
                    if admin.is_active:
                        skipped.append({"id": admin.id, "reason": "Cannot delete active Admin"})
                    else:
                        db.session.delete(admin)
                        deleted_ids.append(admin.id)

            else:
                return jsonify({'error': 'Invalid action'}), 400

            db.session.commit()

            return jsonify({
                'success': True,
                'message': f'Bulk {action} completed for {len(admins)} administrators',
                'deleted': deleted_ids,
                'skipped': skipped
            })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# API Routes for Invitations
@admin_bp.route('/api/admin/invitations')
@login_required
@super_admin_required
def get_invitations():
    # from app import Organization,Invitation,Admin # Ensure models are imported
    """Get all invitations with filtering"""
    # ... (existing get_invitations logic) ...
    try:
        # Join with Organization and User (invited_by) tables
        query = Invitation.query.join(
            Organization, Invitation.organization_id == Organization.id, isouter=True
        ).join(
            Admin, Invitation.invited_by_id == Admin.id, isouter=True
        )

        org_id = request.args.get('organization_id')
        status = request.args.get('status')
        inviter = request.args.get('invited_by_id')
        search = request.args.get('search')
        
        if org_id:
            
            try:
                org_id_int= int(org_id)
                query = query.filter(Invitation.organization_id == org_id_int)
                current_app.logger.info(f"here we check invalid org id:  {org_id_int}")
            except ValueError:
                current_app.logger.warning(f"Invalid org_id passed:  {org_id}")


        if status in ['Accepted', 'Pending', 'Expired']:
            query = query.filter(Invitation.status == status)


        if inviter:
            try:
                inviter_int= int(inviter)
                query = query.filter(Invitation.invited_by_id == inviter_int)
                current_app.logger.info(f"here we check invalid invited_by_id id:  {inviter_int}")
            
            except ValueError:
                current_app.logger.warning(f"Invalid invited_by_id passed:  {inviter}")
        
        if search:
            search_term = f'%{search}%'
            query = query.filter(
                or_(
                    Invitation.email.ilike(search_term)
                )
            ) 
        # ... (existing filtering logic) ...
        invitations = query.order_by(Invitation.created_at.desc()).limit(20).all()
        
        return jsonify([{
            'id': inv.id,
            'email': inv.email,
            'role': inv.role,
            'status': inv.status,
            'organization': {
                'id': inv.organization.id,
                'name': inv.organization.name
            } if inv.organization else None,
            'invited_by': {
                'id': inv.invited_by.id,
                'name': inv.invited_by.name
            } if inv.invited_by else None,
            'sent_at': inv.sent_at.isoformat() if hasattr(inv, 'sent_at') and inv.sent_at else None,
            'expires_at': inv.expires_at.isoformat() if hasattr(inv, 'expires_at') and inv.expires_at else None,
            'created_at': inv.created_at.isoformat() if hasattr(inv, 'created_at') else None
        } for inv in invitations])
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@admin_bp.route('/api/admin/invitations', methods=['POST'])
@login_required
@super_admin_required
def send_invitation():

    try:
        data = request.get_json() or {}
        email = data.get('email')
        role = data.get('role')
        organization_id = data.get('organization_id')

        # ===============================
        # 1. Validate Input
        # ===============================  

        allowed_roles = ["org_admin", "manager", "staff", "location_admin"]

        if role not in allowed_roles:
            return jsonify({"error": "Only admin roles can be invited."}), 400

        if not email or not role:
            return jsonify({'error': 'Email and role are required'}), 400

        if organization_id is None:
            return jsonify({'error': 'Organization ID is required'}), 400

        # ===============================
        # 2. Validate Organization
        # ===============================  
        organization = Organization.query.get(organization_id)
        if not organization:
            return jsonify({'error': 'Organization not found'}), 404


        # ===============================
        # 3. Check if user already exists in this organization
        # ===============================  
        existing_user = Admin.query.filter_by(
            email=email,
            organization_id=organization_id
        ).first()

        if existing_user:
            return jsonify({'error': 'User with this email already exists'}), 400

        # ===============================
        # 4. Check pending invitation (for same org only)
        # ===============================  
        existing_invite = Invitation.query.filter_by(
            email=email,
            organization_id=organization_id,
            status='pending'
        ).first()

        if existing_invite:
            return jsonify({'error': 'Pending invitation already exists for this email'}), 400

        # ===============================
        # 5. Create the Invitation
        # ===============================  
        invitation = Invitation(
            email=email,
            role=role,
            organization=organization,
            invited_by_id=current_user.id,
            status='pending',
            expires_at=datetime.utcnow() + timedelta(days=7)
        )

        db.session.add(invitation)
        db.session.commit()  # required to assign ID

        # ===============================
        # 6. Send Email
        # ===============================  
        try:
            send_invitation_email(invitation.id)
        
        except Exception as e:
            current_app.logger.error(f"Email failed: {e}")
            return jsonify({
                'success': True,
                'message': 'Invitation created but email failed.',
                'invitation_id': invitation.id
            }), 201

        return jsonify({
            'success': True,
            'message': 'Invitation sent successfully',
            'invitation_id': invitation.id
        }), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error in send_invitation: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500



# NEW: Update Invitation (e.g., to change role, extend expiry, or manually change status)
@admin_bp.route('/api/admin/invitations/<int:invitation_id>', methods=['PUT', 'PATCH'])
@login_required
@super_admin_required
def update_invitation(invitation_id):
    """Update an existing invitation"""
    # from app import db, Invitation, Organization # Ensure models are imported
    try:
        invitation = Invitation.query.get_or_404(invitation_id)
        data = request.get_json()

        if 'email' in data:
            # Check for email uniqueness if updated, ensure it's not taken by another user/pending invite
            if Invitation.query.filter(Invitation.email == data['email'], Invitation.id != invitation_id, Invitation.status == 'pending').first():
                 return jsonify({'error': 'Another pending invitation exists for this email.'}), 409
            # You might also want to check against the Admin model if the email is now taken
            # from app import Admin
            if Admin.query.filter_by(email=data['email']).first():
                return jsonify({'error': 'An administrator already uses this email.'}), 409
            invitation.email = data['email']
        
        if 'role' in data:
            invitation.role = data['role']
        
        if 'organization_id' in data:
            organization = Organization.query.get(data['organization_id'])
            if not organization:
                return jsonify({'error': 'Organization not found.'}), 404
            invitation.organization_id = data['organization_id']
        
        if 'status' in data:
            # Be careful allowing arbitrary status changes without business logic checks
            invitation.status = data['status']
        
        if 'expires_at' in data:
            invitation.expires_at = datetime.fromisoformat(data['expires_at'])
        
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Invitation updated successfully',
            'invitation': {
                'id': invitation.id,
                'email': invitation.email,
                'role': invitation.role,
                'status': invitation.status
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# INDIVIDUAL RESEND
@admin_bp.route('/api/admin/invitations/<int:invitation_id>/resend', methods=['POST'])
@login_required
@super_admin_required
def resend_invitation(invitation_id):
    """Resend an invitation"""
    try:
        # Eager load the organization relationship when fetching the invitation
        invitation = Invitation.query.options(joinedload(Invitation.organization)).get_or_404(invitation_id)
        
        if invitation.status not in ['pending', 'expired']:
            return jsonify({'error': 'Can only resend pending or expired invitations'}), 400

        # Generate a new token and extend expiration
        invitation.generate_new_token()
        invitation.expires_at = datetime.utcnow() + timedelta(days=7)
        db.session.commit()

        # Resend email
        try:
            send_invitation_email(invitation.id)
        except Exception as email_error:
            return jsonify({'error': f'Failed to send email: {str(email_error)}'}), 500

        return jsonify({'success': True, 'message': 'Invitation resent successfully'})

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to resend invitation {invitation_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

# bulk deleting
@admin_bp.route('/api/admin/invitations/bulk-delete', methods=['POST'])
@login_required
@super_admin_required
def bulk_delete_invitations():
    data = request.get_json()
    invitation_ids = data.get("ids", [])

    if not invitation_ids or not isinstance(invitation_ids, list):
        return jsonify({"error": "List of invitation IDs is required."}), 400

    deleted_ids = []
    skipped = []

    try:
        for invitation_id in invitation_ids:
            invitation = Invitation.query.get(invitation_id)
            if not invitation:
                skipped.append({"id": invitation_id, "reason": "Not found"})
                continue
            if invitation.status in ['pending', 'accepted']:
                skipped.append({"id": invitation_id, "reason": f"Cannot delete {invitation.status} invitation"})
                continue

            db.session.delete(invitation)
            deleted_ids.append(invitation_id)

        db.session.commit()

        return jsonify({
            "success": True,
            "deleted": deleted_ids,
            "skipped": skipped,
            "message": f"Deleted {len(deleted_ids)} invitation(s), skipped {len(skipped)}."
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


# NEW: delete Invitation
@admin_bp.route('/api/admin/invitations/<int:invitation_id>/delete', methods=['POST'])
@login_required
@super_admin_required
def delete_invitation(invitation_id):
    """delete an invitation"""
    # from app import db, Invitation # Ensure models are imported
    data = request.get_json()
    invitation_id = data.get('id')
    if not invitation_id:
        return jsonify({"error": "Invitation id is required"}), 400
    
    try:
        invitation = Invitation.query.get_or_404(invitation_id)
        if not invitation:
            return jsonify({"error": "Invitation not found"}), 400
        
        if invitation.status == 'pending':
            return jsonify({'error': 'You cant delete pending Invitation'}), 400

        db.session.delete(invitation)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Invitation cancelled successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/invitations/<int:invitation_id>/cancel', methods=['POST'])
@login_required
@super_admin_required
def cancel_invitation(invitation_id):
    """Cancel an invitation"""
    # from app import db, Invitation # Ensure models are imported
    data = request.get_json()
    invitation_id = data.get('id')
    
    if not invitation_id:
        return jsonify({"error": "Invitation id is required"}), 400

    try:
        invitation = Invitation.query.get_or_404(invitation_id)

        if invitation.status == "cancelled":
            return jsonify({"message": "Invitation already cancelled."}), 200
        
        invitation.status = "cancelled"
        # Optional: if you track timestamps
        # invitation.cancelled_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'message': 'Invitation cancelled successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# BULK RESEND AND CANCEL
@admin_bp.route('/api/admin/invitations/bulk-action', methods=['POST'])
@login_required
@super_admin_required
def bulk_invitation_action():
    
    """Perform bulk actions on invitations"""
    try:
        data = request.get_json()
        action = data.get('action')
        ids = data.get('ids', [])
        
        if not ids or action not in ['cancel', 'resend']:
            return jsonify({'error': 'No invitations'}), 400
        # invitations = Invitation.query.filter(Invitation.id.in_(invitation_ids)).all() 
       
       # Fetch invitations and eager load the organization relationship for bulk actions
        invitations = Invitation.query.options(joinedload(Invitation.organization)).filter(Invitation.id.in_(ids)).all()
        
        # Track results for the response
        success_count = 0
        failed_invitations = []

        if action == 'resend':
            for inv in invitations:
                # Allow resending if status is 'pending' or 'expired'
                if inv.status == 'pending' or inv.status == 'expired':
             
                    try:
                        # Generate a new token for each resent invitation
                        inv.generate_new_token() # Call the method we added to the Invitation model
                        inv.expires_at = datetime.utcnow() + timedelta(days=7)
                        inv.status = 'pending' # Reset status to pending

                        db.session.add(inv) # Add to session if not already tracked (should be)
                            # We will commit once after the loop for efficiency
                            # Send email
                        send_invitation_email(inv.id)
                        success_count += 1
                    except Exception as e:
                        # Log the error for this specific invitation
                        current_app.logger.error(
                            f"Failed to resend invitation {inv.id} to {inv.email}: {str(e)}"
                        )                          
                        failed_invitations.append({'id': inv.id, 'email': inv.email, 'error': str(e)})
                else:
                    
                    # Log if an invitation cannot be resent due to its status
                    current_app.logger.info(
                        f"Skipping resend for invitation {inv.id} to {inv.email}: Status is {inv.status}"
                    )
                    failed_invitations.append({
                        'id': inv.id,
                        'email': inv.email,
                        'error': f"Cannot resend invitation with status: {inv.status}"
                    })


            # Commit all successful changes at once after the loop
            if success_count > 0:
                db.session.commit()
            else:
                db.session.rollback() # Rollback if no successful changes were committed

            message = f"Successfully resent {success_count} invitations."
            if failed_invitations:
                message += f" Failed to resend {len(failed_invitations)} invitations."
                current_app.logger.warning(
                    f"Bulk resend completed with failures: {failed_invitations}"
                )

            return jsonify({
                'success': True if success_count > 0 else False,
                'message': message,
                'failed_invitations': failed_invitations
            })

        elif action == 'cancel':
            # This part can remain similar
            for inv in invitations:
                if inv.status in ['pending', 'expired']: # Only cancel if not already accepted/cancelled
                    inv.status = 'cancelled'
                    db.session.add(inv)
                    success_count += 1
                else:
                    failed_invitations.append({
                        'id': inv.id,
                        'email': inv.email,
                        'error': f"Cannot cancel invitation with status: {inv.status}"
                    })
            db.session.commit()
            message = f"Successfully cancelled {success_count} invitations."
            if failed_invitations:
                message += f" Failed to cancel {len(failed_invitations)} invitations."

            return jsonify({
                'success': True if success_count > 0 else False,
                'message': message,
                'failed_invitations': failed_invitations
            })
        else:
            return jsonify({'error': 'Invalid action'}), 400

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error during bulk invitation action: {str(e)}", exc_info=True)
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500



@admin_bp.route('/api/admin/inviters')
@login_required
@super_admin_required
def get_inviters():
    # from app import Invitation,db,Admin
    """Get all users who have sent invitations (for filter dropdown)"""
    # ... (existing get_inviters logic) ...
    try:
        inviters = db.session.query(Admin.id, Admin.name).join(
            Invitation, Admin.id == Invitation.invited_by_id
        ).distinct().all()
        
        return jsonify([{
            'id': inviter.id,
            'name': inviter.name
        } for inviter in inviters])
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# API Routes for Guests (Invitees)

@admin_bp.route('/api/admin/managed_invitees')
@login_required
@super_admin_required
def get_invitee():
    # from models import EventInvitee,Event
    """
    API: Get all invitees with optional filtering for super admins
    """ 
    try:

        query = Invitee.query.filter(Invitee.confirmed.in_(['Absent', 'Present', 'Confirmed']))
        
         # Filters
        org_id = request.args.get('organization_id')
        position = request.args.get('position')  # Volunteer, Guest, Attendee
        confirmed = request.args.get('confirmed')  # Present, Absent, Confirmed
        search = request.args.get('search')
        
      
        # if org_id:
        # query = query.filter(Invitee.organization_id == org_id)
        
        if org_id:
            
            try:
                org_id_int= int(org_id)
                query = query.filter(Invitee.organization_id == org_id_int)
                current_app.logger.info(f"here we check invalid org id:  {org_id_int}")
            except ValueError:
                current_app.logger.warning(f"Invalid org_id passed:  {org_id}")

        if confirmed in ['Absent', 'Present','Confirmed']:
            query = query.filter(Invitee.confirmed == confirmed)

        if position in ['Volunteer', 'Guest', 'Attendee']:
            query = query.filter(Invitee.position == position)

        if search:
            search_term = f'%{search}%'
            query = query.filter(
                or_(
                    Invitee.name.ilike(search_term),
                    Invitee.email.ilike(search_term),
                    Invitee.phone_number.ilike(search_term)
                )
            ) 

        invitees = query.order_by(Invitee.confirmation_date.desc()).limit(50).all()

        return jsonify([
            {
                'id': i.id,
                'name': i.name,
                'email': i.email,
                'confirmed': i.confirmed,
                'position': i.position,
                'phone_number': i.phone_number,
                'organization': {
                'id': i.organization.id,
                'name': i.organization.name.title()
                } if i.organization else None,
                'created_at': i.register_date.isoformat() if hasattr(i, 'register_date') and i.register_date else None
            } for i in invitees
        ])

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# NEW: Create Invitee (though usually invitees are created via an invitation acceptance flow)

@admin_bp.route('/api/admin/managed_invitees', methods=['POST'])
@login_required
@super_admin_required
def create_invitee():

    """Create a new invitee (guest)"""
    # from app import db, Invitee, Organization # Ensure models are imported
    try:
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        organization_id = data.get('organization_id')
        confirmed_status = data.get('confirmed', 'Confirmed') # Default to 'Confirmed'

        if not name or not email or not organization_id:
            return jsonify({'error': 'Name, email, and organization ID are required.'}), 400
        
        if Invitee.query.filter_by(email=email, organization_id=organization_id).first():
            return jsonify({'error': 'Invitee with this email already exists for this organization.'}), 409

        organization = Organization.query.get(organization_id)
        if not organization:
            return jsonify({'error': 'Organization not found.'}), 404

        # Generate temporary password
        temp_password = secrets.token_urlsafe(8)  # 8-character random password

        new_invitee = Invitee(
            name=name,
            email=email,
            organization_id=organization_id,
            position=data.get('position'),  # optional, can default to None
            confirmed=confirmed_status
        )

        new_invitee.set_password(temp_password)  # Hash the password

        db.session.add(new_invitee)
        db.session.commit()

        try:
            send_invitee_invitation_email(new_invitee.id, temp_password=temp_password)

        except Exception as email_error:
            current_app.logger.error(
                    f"Failed to send invitation email for {new_invitee.email}: {email_error}",
                    exc_info=True
                )
            
            # ✔ FIX: return even if email fails
            return jsonify({
                'success': True,
                'warning': 'Invitee created but email failed to send',
                'invitee': {
                    'id': new_invitee.id,
                    'name': new_invitee.name,
                    'email': new_invitee.email,
                    'position': new_invitee.position,
                    'confirmed': new_invitee.confirmed
                }
            }), 207   # 207 = Multi-Status (good for partial success)

        # EMAIL SENT SUCCESSFULLY
        return jsonify({
            'success': True,
            'message': 'Invitee created successfully',
            'invitee': {
                'id': new_invitee.id,
                'name': new_invitee.name,
                'email': new_invitee.email,
                'position': new_invitee.position,
                'confirmed': new_invitee.confirmed
            }
        }), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# NEW: Update Invitee
@admin_bp.route('/api/admin/managed_invitees/<int:invitee_id>', methods=['PUT', 'PATCH'])
@login_required
@super_admin_required
def update_invitee(invitee_id):
    """Update an existing invitee (guest)"""
    # from app import db, Invitee, Organization # Ensure models are imported
    try:
        invitee = Invitee.query.get_or_404(invitee_id)
        data = request.get_json()

        if 'name' in data:
            invitee.name = data['name']
        if 'email' in data:
            # Check for email uniqueness within the same organization if updated
            if Invitee.query.filter(Invitee.email == data['email'], Invitee.organization_id == invitee.organization_id, Invitee.id != invitee_id).first():
                return jsonify({'error': 'Invitee with this email already exists for this organization.'}), 409
            invitee.email = data['email']
        
        if 'organization_id' in data:
            organization = Organization.query.get(data['organization_id'])
            if not organization:
                return jsonify({'error': 'Organization not found.'}), 404
            invitee.organization_id = data['organization_id']
        
        if 'confirmed' in data:
            invitee.confirmed = data['confirmed'] # e.g., 'Present', 'Absent', 'Confirmed'
        
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Invitee updated successfully',
            'invitee': {
                'id': invitee.id,
                'name': invitee.name,
                'email': invitee.email,
                'phone_number': invitee.phone_number,
                'confirmed': invitee.confirmed,
                'organization_id': invitee.organization_id
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/managed_invitees/bulk-action', methods=['POST'])
@login_required
@super_admin_required
def bulk_manage_invitees():
    """
    Perform bulk actions on managed invitees: delete, mark as present, mark as absent.
    """
    try:
        data = request.get_json()
        invitee_ids = data.get('invitee_ids', [])
        action = data.get('action')

        if not invitee_ids or not action:
            return jsonify({'error': 'Invitees and action are required.'}), 400

        invitees_to_process = Invitee.query.filter(Invitee.id.in_(invitee_ids)).all()

        if not invitees_to_process:
            return jsonify({'error': 'No valid invitees found for the provided IDs.'}), 404

        skipped = []
        updated = []
        deleted = []

        for invitee in invitees_to_process:
            if action == 'delete':
                if invitee.confirmed == 'Present':
                    skipped.append({'id': invitee.id, 'name': invitee.name, 'reason': 'Already present'})
                else:
                    db.session.delete(invitee)
                    deleted.append(invitee.id)

            elif action == 'mark_present':
                if invitee.confirmed == 'Present':
                    skipped.append({'id': invitee.id, 'name': invitee.name, 'reason': 'Already present'})
                else:
                    invitee.confirmed = 'Present'
                    updated.append(invitee.id)

            elif action == 'mark_absent':
                if invitee.confirmed == 'Absent':
                    skipped.append({'id': invitee.id, 'name': invitee.name, 'reason': 'Already absent'})
                else:
                    invitee.confirmed = 'Absent'
                    updated.append(invitee.id)

            else:
                return jsonify({'error': 'Invalid action.'}), 400

        db.session.commit()

        return jsonify({
            'success': True,
            'action': action,
            'deleted': deleted,
            'updated': updated,
            'skipped': skipped,
            'message': f'Bulk action "{action}" completed.'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



# NEW: Delete Invitee
@admin_bp.route('/api/admin/managed_invitees/<int:invitee_id>', methods=['POST'])
@login_required
@super_admin_required
def delete_invitee(invitee_id):
    """Delete an invitee (guest)"""
    # from app import db, Invitee # Ensure models are imported
    try:
        invitee = Invitee.query.get_or_404(invitee_id)
        db.session.delete(invitee)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Invitee deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



# --- Existing Data Export Routes and Error Handlers ---
@admin_bp.route('/api/admin/export')
@login_required
@super_admin_required
def export_data():
    # from app import Invitation,db,Admin,Location,Organization
    """Export management data"""
    # ... (existing export_data logic) ...
    try:
        export_type = request.args.get('type', 'all')
        
        data = {}
        
        if export_type in ['all', 'locations']:
            locations = Location.query.join(Organization).all()
            data['locations'] = [{
                'id': loc.id,
                'name': loc.name,
                'address': getattr(loc, 'address', ''),
                'organization': loc.organization.name,
                'status': 'Active' if loc.is_active else 'Inactive',
                'created_at': loc.created_at.isoformat() if hasattr(loc, 'created_at') else None
            } for loc in locations]
        
        if export_type in ['all', 'administrators']:
            admins = Admin.query.filter(Admin.role.in_(['super_admin', 'org_admin', 'location_admin'])).all()
            data['administrators'] = [{
                'id': admin.id,
                'name': admin.name,
                'email': admin.email,
                'role': admin.role,
                'organization': admin.organization.name if admin.organization else '',
                'status': 'Active' if admin.is_active else 'Inactive',
                'last_login': admin.last_login.isoformat() if hasattr(admin, 'last_login') and admin.last_login else None
            } for admin in admins]
        
        if export_type in ['all', 'invitations']:
            invitations = Invitation.query.order_by(Invitation.created_at.desc()).limit(20).all()
            data['invitations'] = [{
                'id': inv.id,
                'email': inv.email,
                'role': inv.role,
                'status': inv.status,
                'organization': inv.organization.name if inv.organization else '',
                'invited_by': inv.invited_by.name if inv.invited_by else '',
                'sent_at': inv.sent_at.isoformat() if hasattr(inv, 'sent_at') and inv.sent_at else None,
                'expires_at': inv.expires_at.isoformat() if hasattr(inv, 'expires_at') and inv.expires_at else None
            } for inv in invitations]

        # NEW: Add invitees to export if needed
        if export_type in ['all', 'invitees']:
            # from app import Invitee # Ensure Invitee model is imported
            invitees = Invitee.query.order_by(Invitee.confirmation_date.desc()).limit(20).all()
            data['invitees'] = [{
                'id': inv.id,
                'name': inv.name,
                'email': inv.email,
                'confirmed_status': inv.confirmed,
                'organization': inv.organization.name if inv.organization else '',
                'created_at': inv.created_at.isoformat() if hasattr(inv, 'created_at') else None
            } for inv in invitees]

        return jsonify({
            'success': True,
            'data': data,
            'exported_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Error handlers
@admin_bp.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@admin_bp.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Access denied'}), 403

@admin_bp.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'An internal error occurred'}), 500


### API Routes for Events
@admin_bp.route('/api/admin/events')
@login_required
@super_admin_required
def get_events():
    """Get all events with filtering"""
    # from app import Organization, Location, Event # Make sure to import your Event model
    try:
        # query = Event.query.join(Organization).join(Location) # Assuming Event has foreign keys to Organization and Location
        query = Event.query \
            .outerjoin(Organization) \
            .outerjoin(Location) \
            .options(joinedload(Event.organization), joinedload(Event.location))

        # Apply filters
        org_id = request.args.get('organization_id')
        location_id = request.args.get('location_id')
        status = request.args.get('status') # e.g., 'active', 'past', 'upcoming'
        search = request.args.get('search')
        date_filter = request.args.get('date_filter') # e.g., 'today', 'week', 'month'

        # if org_id:
        #     query = query.filter(Event.organization_id == org_id)

        if org_id:
            try:
                org_id_int= int(org_id)
                query = query.filter(Event.organization_id == org_id_int)
                current_app.logger.info(f"here we check invalid org id:  {org_id_int}")
            except ValueError:
                current_app.logger.warning(f"Invalid org_id passed:  {org_id}")


        if location_id:
            try:
                location_id_int =int(location_id)
                query = query.filter(Event.location_id == location_id_int) 
            except ValueError:
                current_app.logger.warning(f"Invalid location_id passed:  {location_id}")
        
        if status:
            # You'll need to define how 'status' is determined in your Event model
            # For example, if you have an 'is_active' column or calculated status based on dates
            if status == 'active':
                query = query.filter(Event.is_active == True) # Example
            elif status == 'upcoming':
                query = query.filter(Event.start_time > datetime.utcnow()) # Example
            elif status == 'past':
                query = query.filter(Event.end_time < datetime.utcnow()) # Example

        if search:
            search_term = f'%{search}%'
            query = query.filter(
                or_(
                    Event.name.ilike(search_term),
                    Event.description.ilike(search_term),
                    Organization.name.ilike(search_term),
                    Location.name.ilike(search_term)
                )
            )
        
        if date_filter:
            now = datetime.utcnow()
            if date_filter == 'today':
                start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
                end_date = now.replace(hour=23, minute=59, second=59, microsecond=999999)
                query = query.filter(Event.start_time >= start_date, Event.start_time <= end_date)
            elif date_filter == 'week':
                start_date = now - timedelta(days=now.weekday()) # Start of current week
                query = query.filter(Event.start_time >= start_date)
            elif date_filter == 'month':
                start_date = now.replace(day=1) # Start of current month
                query = query.filter(Event.start_time >= start_date)
            # You might need to add logic for `end_date` if you want to filter events ending within a period

        events = query.order_by(Event.created_at.desc()).limit(20).all()

        return jsonify([{
            'id': event.id,
            'name': event.name,
            'description': getattr(event, 'description', None),
            'start_time': event.start_time.isoformat() if hasattr(event, 'start_time') else None,
            'end_time': event.end_time.isoformat() if hasattr(event, 'end_time') else None,
            'is_active': getattr(event, 'is_active', True),
            'organization': {
                'id': event.organization.id,
                'name': event.organization.name
            } if event.organization else None,
            'location': {
                'id': event.location.id,
                'name': event.location.name,
                'address': getattr(event.location, 'address', '')
            } if event.location else None,
            'created_at': event.created_at.isoformat() if hasattr(event, 'created_at') else None
        } for event in events])


    except Exception as e:
        return jsonify({'error': str(e)}), 500


# @admin_bp.route('/api/admin/events/<int:event_id>')
# @login_required
# @super_admin_required
# def get_event(event_id):
#     """Get a single event by ID"""
#     # from app import Event # Ensure Event model is imported
#     try:
#         event = Event.query.get_or_404(event_id)

#         return jsonify({
#             'id': event.id,
#             'name': event.name,
#             'description': getattr(event, 'description', None),
#             'start_time': event.start_time.isoformat() if hasattr(event, 'start_time') else None,
#             'end_time': event.end_time.isoformat() if hasattr(event, 'end_time') else None,
#             'is_active': getattr(event, 'is_active', True),
#             'organization': {
#                 'id': event.organization.id,
#                 'name': event.organization.name
#             } if event.organization else None,
#             'location': {
#                 'id': event.location.id,
#                 'name': event.location.name,
#                 'address': getattr(event.location, 'address', '')
#             } if event.location else None,
#             'created_at': event.created_at.isoformat() if hasattr(event, 'created_at') else None
#         })
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/events', methods=['POST'])
@login_required
@super_admin_required
def create_event():
    """Create a new event"""
    # from app import db, Event, Organization, Location # Ensure models are imported
    try:

        data = request.get_json()
        name = data.get('name')
        description = data.get('description')
        organization_id = data.get('organization_id')
        location_id = data.get('location_id')
        start_time_str = data.get('start_time')
        end_time_str = data.get('end_time')
        is_active = data.get('is_active', True)

        if not name or not organization_id or not location_id or not start_time_str or not end_time_str:
            return jsonify({'error': 'Name, organization, location, start time, and end time are required.'}), 400

        # Convert string dates to datetime objects
        start_time = datetime.fromisoformat(start_time_str)
        end_time = datetime.fromisoformat(end_time_str)

        # Basic validation
        if end_time <= start_time:
            return jsonify({'error': 'End time must be after start time.'}), 400
        
        # Check if organization and location exist
        organization = Organization.query.get(organization_id)
        location = Location.query.get(location_id)
        if not organization:
            return jsonify({'error': 'Organization not found.'}), 404
        if not location:
            return jsonify({'error': 'Location not found.'}), 404

        event = Event(
            name=name,
            description=description,
            organization_id=organization_id,
            location_id=location_id,
            start_time=start_time,
            end_time=end_time,
            is_active=is_active
        )
        db.session.add(event)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Event created successfully',
            'event': {
                'id': event.id,
                'name': event.name,
                'is_active': event.is_active
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/events/<int:event_id>', methods=['PUT'])
@login_required
@super_admin_required
def update_event(event_id):
    """Update an existing event"""
    # from app import db, Event, Organization, Location # Ensure models are imported
    try:
        event = Event.query.get_or_404(event_id)
        data = request.get_json()

        event.name = data.get('name', event.name)
        event.description = data.get('description', event.description)
        event.is_active = data.get('is_active', event.is_active)

        organization_id = data.get('organization_id')
        if organization_id:
            organization = Organization.query.get(organization_id)
            if not organization:
                return jsonify({'error': 'Organization not found.'}), 404
            event.organization_id = organization_id

        location_id = data.get('location_id')
        if location_id:
            location = Location.query.get(location_id)
            if not location:
                return jsonify({'error': 'Location not found.'}), 404
            event.location_id = location_id

        start_time_str = data.get('start_time')
        if start_time_str:
            event.start_time = datetime.fromisoformat(start_time_str)

        end_time_str = data.get('end_time')
        if end_time_str:
            event.end_time = datetime.fromisoformat(end_time_str)

        # Re-validate time order if both were updated or implied change
        if event.end_time and event.start_time and event.end_time <= event.start_time:
            return jsonify({'error': 'Updated end time must be after start time.'}), 400

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Event updated successfully',
            'event': {
                'id': event.id,
                'name': event.name,
                'is_active': event.is_active
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/events/<int:event_id>/toggle-status', methods=['POST'])
@login_required
@super_admin_required
def toggle_event_status(event_id):

    """Toggle event active status"""
    # from app import db, Event # Ensure Event model is imported
    try:
        event = Event.query.get_or_404(event_id)
        event.is_active = not event.is_active
        db.session.commit()
        
        return jsonify({
            'success': True,
            'is_active': event.is_active,
            'message': f'Event {"activated" if event.is_active else "deactivated"} successfully'
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



@admin_bp.route('/api/admin/events/bulk-action', methods=['POST'])
@login_required
@super_admin_required
def bulk_event_action():
    """Perform bulk actions on events"""
    deleted_ids = []
    skipped = []

    try:
        data = request.get_json()
        action = data.get('action')
        event_ids = data.get('event_ids', [])

        if not event_ids:
            return jsonify({'error': 'No events selected'}), 400

        events = Event.query.filter(Event.id.in_(event_ids)).all()

        if action == 'activate':
            for event in events:
                if event.is_active:
                    skipped.append({"id": event.id, "reason": "Already activated"})
                    continue
                event.is_active = True

        elif action == 'deactivate':
            for event in events:
                if not event.is_active:
                    skipped.append({"id": event.id, "reason": "Already deactivated"})
                    continue
                event.is_active = False

        elif action == 'delete':
            for event in events:
                if event.is_active:
                    skipped.append({"id": event.id, "reason": "Cannot delete active event"})
                    continue
                db.session.delete(event)
                deleted_ids.append(event.id)

        else:
            return jsonify({'error': 'Invalid action'}), 400

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Bulk {action} completed.',
            'deleted': deleted_ids,
            'skipped': skipped
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# NEW: delete Invitation
@admin_bp.route('/api/admin/events/<int:event_id>/delete', methods=['POST'])
@login_required
@super_admin_required
def delete_event(event_id):

    """Delete an event, unless it is active and upcoming."""
    try:
        event = Event.query.get_or_404(event_id)

        now = datetime.utcnow()
        is_upcoming = event.start_time > now

        # Prevent deletion if the event is active and upcoming
        if is_upcoming and event.is_active:
            return jsonify({'error': 'You cannot delete an active upcoming event.'}), 400

        db.session.delete(event)
        db.session.commit()

        return jsonify({'success': True, 'message': 'Event deleted successfully.'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# Error handlers
@admin_bp.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@admin_bp.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Access denied'}), 403

@admin_bp.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'An internal error occurred'}), 500