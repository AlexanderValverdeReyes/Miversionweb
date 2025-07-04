const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Servir archivos estáticos del frontend
app.use(express.static(path.join(__dirname, '../Frontend')));

// Conexión a SQLite
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) console.error(err.message);
    console.log('Conectado a SQLite.');
});

// Crear tabla de usuarios si no existe
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        genero TEXT NOT NULL
    )
`);

// Crear tabla historial si no existe
db.run(`
    CREATE TABLE IF NOT EXISTS historial (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        termino TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`);

// Ruta para registro
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
                res.json({ success: true, user_id: this.lastID });
            }
        );
    } catch (err) {
        res.status(500).json({ error: 'Error en el servidor.' });
    }
});

// Ruta para login
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
            res.json({ success: true, user_id: user.id });
        }
    );
});

// Ruta para guardar búsqueda
app.post('/api/historial', (req, res) => {
    const { user_id, termino } = req.body;
    if (!user_id || !termino) {
        return res.status(400).json({ error: 'Faltan datos.' });
    }

    // Evitar duplicado inmediato (último término igual)
    db.get(
        `SELECT termino FROM historial 
         WHERE user_id = ? 
         ORDER BY timestamp DESC LIMIT 1`,
        [user_id],
        (err, row) => {
            if (err) return res.status(500).json({ error: 'Error al verificar historial.' });

            if (row && row.termino.toLowerCase() === termino.toLowerCase()) {
                return res.json({ success: true, message: "Búsqueda duplicada ignorada." });
            }

            // Insertar término nuevo
            db.run(
                'INSERT INTO historial (user_id, termino) VALUES (?, ?)',
                [user_id, termino],
                function (err) {
                    if (err) {
                        return res.status(500).json({ error: 'Error al guardar historial.' });
                    }
                    res.json({ success: true });
                }
            );
        }
    );
});

// Ruta para obtener historial por usuario
app.get('/api/historial/:user_id', (req, res) => {
    const userId = req.params.user_id;
    db.all(
        'SELECT termino, timestamp FROM historial WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10',
        [userId],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ error: 'Error al obtener historial.' });
            }
            res.json(rows);
        }
    );
});

// Ruta raíz
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../Frontend/index.html'));
});

// Iniciar servidor
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Servidor backend en http://localhost:${PORT}`);
});