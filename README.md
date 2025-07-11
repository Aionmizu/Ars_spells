# Spell Combos

A web application for tracking and rating spell combinations. Users can add new combos, view existing ones, and vote on their effectiveness.

## Features

- View a table of spell combos with details like name, spells used, description, requirements, tags, creator, and patched status
- Add new spell combos through a simple form
- Vote on combos (thumbs up/down)
- Automatic patching of combos that receive 5 or more negative votes in the last 30 days
- Responsive design that works on mobile and desktop

## Technology Stack

- **Backend**: Flask
- **Database**: SQLite
- **Frontend**: HTML, CSS, HTMX for dynamic updates without page reloads
- **Deployment**: Render.com

## Local Development

1. Clone the repository
2. Create a virtual environment:
   ```
   python -m venv .venv
   .venv\Scripts\activate  # On Windows
   source .venv/bin/activate  # On macOS/Linux
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Run the application:
   ```
   python app.py
   ```
5. Open http://localhost:5000 in your browser

## Deployment on Render.com

This application is configured for easy deployment on Render.com:

1. Fork or clone this repository to your GitHub account
2. Sign up for a Render.com account
3. Create a new Web Service and connect your GitHub repository
4. Render will automatically detect the configuration from the `render.yaml` file
5. The application will be deployed and available at the URL provided by Render

## Database Structure

The application uses two main tables:

### Combos Table
- `id`: Primary key
- `name`: Name of the combo
- `spells`: List of spells used in the combo
- `description`: Description of how the combo works
- `requirement`: Any special requirements for the combo
- `tags`: Tags for categorizing the combo
- `creator`: Name of the person who created the combo
- `created_at`: Timestamp when the combo was added
- `patched`: Boolean indicating if the combo has been patched

### Votes Table
- `id`: Primary key
- `combo_id`: Foreign key referencing the combos table
- `vote`: 1 for positive vote, 0 for negative vote
- `voter_hash`: Hash of the voter's IP address to prevent multiple votes
- `voted_at`: Timestamp when the vote was cast

## License

This project is open source and available under the [MIT License](LICENSE).