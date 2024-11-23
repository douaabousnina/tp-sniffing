from flask import Flask, request, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename
from scapy.all import sniff, Dot11, Dot11Elt
from collections import defaultdict
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads' 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def extract_ap_names_and_count_associations(pcap_file):
    ap_info = {}
    association_counts = defaultdict(int)

    def parse(packet):
        if packet.haslayer(Dot11):
            if packet.type == 0 and packet.subtype in [8, 5]:
                bssid = packet.addr2
                ssid = packet[Dot11Elt].info.decode(errors="ignore") if packet.haslayer(Dot11Elt) else "<Unknown>"
                ap_info[bssid] = ssid

            if packet.type == 0 and packet.subtype == 0:
                bssid = packet.addr3
                if bssid:
                    association_counts[bssid] += 1

    sniff(offline=pcap_file, prn=parse)

    results = []
    total_attempts = 0
    for bssid, count in association_counts.items():
        ssid = ap_info.get(bssid, "<SSID inconnu>")
        results.append((ssid, bssid, count))
        total_attempts +=count

    return results, total_attempts


ALLOWED_EXTENSIONS = {'pcap'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Aucun fichier sélectionné')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '' or not allowed_file(file.filename):
            flash('Fichier invalide. Veuillez télécharger un fichier avec l\'extension .pcap')
            return redirect(request.url)
        
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash(f'Fichier {filename} téléchargé avec succès !')

        return redirect(url_for('results', filename=filename))
    
    return render_template('home.html')


@app.route('/results')
def results():
    file_name = request.args.get('filename')  # Use 'file_name' to match the variable name

    if not file_name:
        flash("Filename is missing.")
        return redirect(url_for('upload_file'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)

    if not os.path.isfile(file_path):
        flash("The file does not exist.")
        return redirect(url_for('upload_file'))  # Redirect if the file is not found

    results, total_attempts = extract_ap_names_and_count_associations(file_path)

    return render_template('results.html', filename=file_name, results=results, total_attempts=total_attempts)


if __name__ == "__main__":
    try:
        app.run(debug=True, use_reloader=False)
    except SystemExit as e:
        print(f"App terminated: {e}")
