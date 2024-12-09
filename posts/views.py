from cryptography.fernet import Fernet
from flask import Blueprint, render_template, flash, url_for, redirect, request
from flask_login import current_user, login_required
from sqlalchemy.sql.functions import user

from posts.forms import PostForm

from sqlalchemy import desc

from config import db, Post, roles_required, Role, logger, User

posts_bp = Blueprint('posts', __name__, template_folder='templates')


# posts routes
@posts_bp.route('/create', methods=('GET', 'POST'))
@login_required
@roles_required('end_user')
def create():
    form = PostForm()
    encryption_key = User.generate_encryption_key()
    if form.validate_on_submit():
        new_post = Post(userid=current_user.get_id(), title=form.title.data, body=form.body.data)
        new_post.set_encrypted_content(form.title.data, form.body.data, encryption_key)
        db.session.add(new_post)
        db.session.commit()
        logger.info('[User: %s, Role: %s, Post ID: %d, IP: %s] Post Created',
                    current_user.email,
                    current_user.role,
                    new_post.id,
                    request.remote_addr
                    )
        flash('Post created', category='success')
        return redirect(url_for('posts.post', _external=True).replace("http://", "https://"))
    return render_template('posts/create.html', form=form, current_user=current_user, Role=Role)


@posts_bp.route('/posts')
@login_required
@roles_required('end_user')
def post():
    all_posts = Post.query.order_by(desc('id')).all()
    encryption_key = User.generate_encryption_key()  # Get encryption key
    for post in all_posts:
        decrypted_content = post.get_decrypted_content(encryption_key)
        post.title = decrypted_content['title']
        post.body = decrypted_content['body']
    return render_template('posts/posts.html', posts=all_posts, current_user=current_user, Role=Role)


@posts_bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
@roles_required('end_user')
def update(id):
    post_to_update = Post.query.filter_by(id=id).first()
    if not post_to_update:
        return redirect(url_for('posts.post', _external=True).replace("http://", "https://"))
    form = PostForm()

    # Check if the current user is the owner of the post
    if post_to_update.userid != current_user.id:
        logger.warning('[User: %s, Role: %s, Post ID: %d, URL: %s, IP: %s] Unauthorized post update attempt',
                       current_user.email,
                       current_user.role,
                       post_to_update.id,
                       request.url,
                       request.remote_addr
                       )
        flash("You are not authorized to update this post.", category='danger')
        return redirect(url_for('posts.post', _external=True).replace("http://", "https://"))

    if form.validate_on_submit():
        encryption_key = User.generate_encryption_key()  # Get encryption key
        post_to_update.set_encrypted_content(form.title.data, form.body.data, encryption_key)
        logger.info('[User: %s, Role: %s, Post ID: %d, IP: %s] Post updated', current_user.email,
                    current_user.role,
                    post_to_update.id,
                    request.remote_addr
                    )
        flash('Post updated', category='success')
        return redirect(url_for('posts.post', _external=True).replace("http://", "https://"))

    # Decrypt the current title and body for editing
    encryption_key = User.generate_encryption_key()  # Get encryption key
    decrypted_content = post_to_update.get_decrypted_content(encryption_key)

    form.title.data = decrypted_content['title']
    form.body.data = decrypted_content['body']

    return render_template('posts/update.html', form=form, current_user=current_user, Role=Role)


@posts_bp.route('/<int:id>/delete')
@login_required
@roles_required('end_user')
def delete(id):
    post_to_delete = Post.query.filter_by(id=id).first()
    if not post_to_delete:
        flash("Post not found", category='danger')
        return redirect(url_for('posts.post', _external=True).replace("http://", "https://"))

    if post_to_delete.userid != current_user.id:
        logger.info('[User: %s, Role: %s, Post ID: %d, URL: %s, IP: %s] Unauthorized post deletion attempt',
                    current_user.email,
                    current_user.role,
                    post_to_delete.id,
                    request.url,
                    request.remote_addr
                    )
        flash("You are not authorized to delete this post")
        return redirect(url_for('posts.post', _external=True).replace("http://", "https://"))

    logger.info('[User: %s, Role: %s, Post ID: %d, IP: %s] Post deleted',
                current_user.email,
                current_user.role,
                post_to_delete.id,
                request.remote_addr
                )
    db.session.delete(post_to_delete)
    db.session.commit()

    flash('Post deleted', category='success')
    return redirect(url_for('posts.post', _external=True).replace("http://", "https://"))
