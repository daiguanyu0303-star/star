{ pkgs }: {
  deps = [
    pkgs.python311
    pkgs.python311Packages.flask
    pkgs.python311Packages.flask-jwt-extended
    pkgs.python311Packages.flask-cors
    pkgs.python311Packages.python-dotenv
    pkgs.python311Packages.bcrypt
    pkgs.python311Packages.pillow
  ];
  env = {
    PYTHONPATH = ".";
    FLASK_APP = "main.py";
  };
}