from app import app

if __name__ == '__main__':
    # Run without the auto-reloader so it stays stable when launched in background
    app.run(debug=True, port=50010, use_reloader=False)
