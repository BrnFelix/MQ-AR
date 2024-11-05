const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Conexão com o MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/monitoramento_qualidade_ar';
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Conectado ao MongoDB!'))
  .catch((err) => console.error('Erro ao conectar ao MongoDB:', err));

// ==================
// Definição dos Esquemas e Modelos
// ==================

// Esquema de Usuários
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  email: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);

// Esquema de Dispositivos
const deviceSchema = new mongoose.Schema({
  deviceId: { type: String, unique: true },
  userId: mongoose.Schema.Types.ObjectId,
  deviceName: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const Device = mongoose.model('Device', deviceSchema);

// Esquema de Leituras
const readingSchema = new mongoose.Schema({
  deviceId: mongoose.Schema.Types.ObjectId,
  timestamp: { type: Date, default: Date.now },
  temperature: Number,
  humidity: Number,
  gasLevel: Number,
  createdAt: { type: Date, default: Date.now },
});

const Reading = mongoose.model('Reading', readingSchema);

// Configuração de chaves secretas e duração dos tokens
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
const ACCESS_TOKEN_EXPIRATION = '15m';
const REFRESH_TOKEN_EXPIRATION = '7d';

function generateAccessToken(payload) {
  return jwt.sign(payload, ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRATION });
}

function generateRefreshToken(payload) {
  return jwt.sign(payload, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRATION });
}

// Middleware para verificar o token JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// ==================
// Rotas de Usuários
// ==================

// Registro de usuário
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;
  const existingUser = await User.findOne({ email });

  if (existingUser) {
    return res.status(400).json({ error: 'Usuário já existe' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, password: hashedPassword, email });

  try {
    const savedUser = await newUser.save();
    res.status(201).json({ _id: savedUser._id, username: savedUser.username, email: savedUser.email });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao registrar usuário' });
  }
});

// Login de usuário
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Usuário ou senha inválidos' });
  }

  const payload = { userId: user._id, email: user.email, username: user.username };
  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload);

  res.json({ accessToken, refreshToken });
});

// ==================
// Rotas de Dispositivos
// ==================

// Registro de dispositivo
app.post('/api/devices', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { deviceId, deviceName } = req.body;

  const existingDevice = await Device.findOne({ deviceId, userId });
  if (existingDevice) {
    return res.status(400).json({ error: 'Dispositivo já cadastrado para o usuário' });
  }

  const newDevice = new Device({ deviceId, userId, deviceName });

  try {
    await newDevice.save();
    res.status(201).json(newDevice);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao registrar dispositivo' });
  }
});

// Remover dispositivo
app.delete('/api/devices/:deviceId', authenticateToken, async (req, res) => {
  try {
    const device = await Device.findOneAndDelete({ deviceId: req.params.deviceId, userId: req.user.userId });
    if (!device) {
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }
    res.status(200).json({ message: 'Dispositivo removido com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao remover dispositivo' });
  }
});

// ==================
// Rotas de Leituras
// ==================

// Registrar leitura
app.post('/api/readings', authenticateToken, async (req, res) => {
  const { deviceId, temperature, humidity, gasLevel } = req.body;

  try {
    const newReading = new Reading({ deviceId, temperature, humidity, gasLevel });
    await newReading.save();
    res.status(201).json(newReading);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao registrar leitura' });
  }
});

// Listar leituras de um dispositivo
app.get('/api/readings/:deviceId', authenticateToken, async (req, res) => {
  try {
    const readings = await Reading.find({ deviceId: req.params.deviceId }).sort({ timestamp: -1 });
    res.status(200).json(readings);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar leituras' });
  }
});

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

module.exports = (req, res) => {
  res.status(200).send("Sua aplicação está funcionando!");
};
