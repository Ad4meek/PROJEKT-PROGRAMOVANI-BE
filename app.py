from flask import Flask, render_template, url_for, request, redirect
from pymongo import MongoClient
import mimetypes
mimetypes.add_type('application/javascript', '.js')
mimetypes.add_type('text/css', '.css')

app = Flask(__name__,
            template_folder='C:\\Users\\pavel.skala\\PROJEKT-PROGRAMOVANI-BE\\www',
            static_folder='C:\\Users\\pavel.skala\\PROJEKT-PROGRAMOVANI-BE\\wwwassets',
            static_url_path='/assets')

client = MongoClient("localhost", 27017)
