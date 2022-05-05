from . import db
from flask import Blueprint, render_template, request, flash
from flask_login import login_required, current_user
from .models import Note

views = Blueprint('views', __name__)


# @views.route('/', methods=['GET','POST'])
# @login_required
# def home():
#     if request.method == 'POST':
#         note = request.form.get('note')
#         new_note = Note(data=note, user_id = current_user.id)
#         db.session.add(new_note)
#         db.session.commit()
#         flash('Запись добавлена', category='success')
        
#     return render_template('home.html', user = current_user)
@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        note = request.form.get('note')

        if len(note) < 1:
            flash('Введите запись', category='error')
        else:
            new_note = Note(data=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Note added!', category='success')

    return render_template("home.html", user=current_user)