const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Configuración para servir archivos estáticos (frontend)
app.use(express.static(path.join(__dirname, '../Frontend')));

// Conexión a SQLite
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) console.error(err.message);
    console.log('Conectado a SQLite.');
});

// Crear tabla de usuarios (con campos adicionales para el registro)
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        genero TEXT NOT NULL
    )
`);

// Ruta de registro (POST /api/register)
app.post('/api/register', async (req, res) => {
    const { nombre, email, password, genero } = req.body;
    
    if (!nombre || !email || !password || !genero) {
        return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        db.run(
            'INSERT INTO users (nombre, email, password_hash, genero) VALUES (?, ?, ?, ?)',
            [nombre, email, passwordHash, genero],
            function (err) {
                if (err) {
                    return res.status(400).json({ error: 'El correo ya está registrado.' });
                }
                res.json({ 
                    success: true, 
                    user_id: this.lastID 
                });
            }
        );
    } catch (err) {
        res.status(500).json({ error: 'Error en el servidor.' });
    }
});

// Ruta de login (POST /api/login)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Correo y contraseña son obligatorios.' });
    }

    db.get(
        'SELECT id, email, password_hash FROM users WHERE email = ?',
        [email],
        async (err, user) => {
            if (err || !user) {
                return res.status(401).json({ error: 'Correo no encontrado.' });
            }
            const isValid = await bcrypt.compare(password, user.password_hash);
            if (!isValid) {
                return res.status(401).json({ error: 'Contraseña incorrecta.' });
            }
            res.json({ 
                success: true, 
                user_id: user.id 
            });
        }
    );
});

// Ruta raíz para servir login.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../Frontend/index.html'));
});

// Iniciar servidor
const PORT = 5000; // Usamos el puerto 5000 como en tus fetch
app.listen(PORT, () => {
    console.log(`Servidor backend en http://localhost:${PORT}`);
});