const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

// Conexão com o MongoDB
mongoose.connect('mongodb://localhost:27017/air-quality-monitor', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('Conectado ao MongoDB! Servidor rodando na porta ' + PORT);
}).catch((err) => {
  console.error('Erro ao conectar ao MongoDB:', err);
});

app.use(express.json()); // Middleware para analisar JSON

// ==================
// Definição dos Esquemas e Modelos
// ==================

// Esquema de Usuários
const userSchema = new mongoose.Schema({
  username: String,
  password: String, // Será armazenada como hash
  email: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);

// Esquema de Dispositivos
const deviceSchema = new mongoose.Schema({
  deviceId: String, // ID único do ESP32
  userId: mongoose.Schema.Types.ObjectId, // Referência ao usuário
  deviceName: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const Device = mongoose.model('Device', deviceSchema);

// Esquema de Leituras
const readingSchema = new mongoose.Schema({
  deviceId: mongoose.Schema.Types.ObjectId, // Referência ao dispositivo
  timestamp: { type: Date, default: Date.now },
  temperature: Number,
  humidity: Number,
  gasLevel: Number, // Poluição em ppm
  createdAt: { type: Date, default: Date.now },
});

const Reading = mongoose.model('Reading', readingSchema);

// Middleware para verificar o token JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user; // Salva o usuário decifrado no request
    next();
  });
};

// ==================
// Rotas de Usuários
// ==================

// Registro de usuário
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({
    username,
    password: hashedPassword,
    email,
    createdAt: new Date(),
    updatedAt: new Date()
  });

  try {
    const savedUser = await newUser.save();
    res.status(201).send({
      _id: savedUser._id,
      username: savedUser.username,
      email: savedUser.email,
      createdAt: savedUser.createdAt,
      updatedAt: savedUser.updatedAt,
      message: "Usuário registrado com sucesso!"
    });
  } catch (err) {
    res.status(500).send({ error: "Erro ao registrar usuário" });
  }
});

// Login de usuário
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Usuário ou senha inválidos' });
  }

  const token = jwt.sign({ userId: user._id }, 'secret_key', { expiresIn: '1h' });
  res.json({ message: 'Login realizado com sucesso', token });
});

// Obter informações do usuário
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    res.status(200).json(user);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar usuário' });
  }
});

// Atualizar usuário
app.put('/api/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { username, email } = req.body;

  try {
    const updatedUser = await User.findByIdAndUpdate(
      id,
      { username, email, updatedAt: new Date() },
      { new: true }
    );
    if (!updatedUser) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    res.status(200).json(updatedUser);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao atualizar usuário' });
  }
});

// Deletar usuário
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const deletedUser = await User.findByIdAndDelete(id);
    if (!deletedUser) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    res.status(200).json({ message: 'Usuário deletado com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao deletar usuário' });
  }
});

// ==================
// Rotas de Dispositivos
// ==================

// Registro de dispositivo (com lógica para reutilizar ID)
app.post('/api/devices', authenticateToken, async (req, res) => {
  const userId = req.user.userId; // Obtém o ID do usuário do token

  try {
    // Procura um dispositivo cujo deviceName (apelido) seja null
    let device = await Device.findOne({ userId, deviceName: null });

    if (!device) {
      // Se não encontrar, cria um novo dispositivo apenas com o deviceId
      const newDevice = new Device({ deviceId: new mongoose.Types.ObjectId().toString(), userId });
      device = await newDevice.save();
    }

    res.status(201).json({
      _id: device._id,
      deviceId: device.deviceId,
      deviceName: device.deviceName,
      userId: device.userId,
      createdAt: device.createdAt,
      updatedAt: device.updatedAt,
      message: "ID de dispositivo obtido com sucesso!"
    });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao registrar ou buscar dispositivo' });
  }
});

// Listar dispositivos de um usuário
app.get('/api/devices/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;

  try {
    const devices = await Device.find({ userId });
    res.json(devices);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar dispositivos' });
  }
});

// Atualizar dispositivo
app.put('/api/devices/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { deviceId, deviceName } = req.body;

  try {
    const updatedDevice = await Device.findByIdAndUpdate(
      id,
      { deviceId, deviceName, updatedAt: new Date() },
      { new: true }
    );
    if (!updatedDevice) {
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }
    res.status(200).json(updatedDevice);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao atualizar dispositivo' });
  }
});

// Deletar dispositivo
app.delete('/api/devices/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const deletedDevice = await Device.findByIdAndDelete(id);
    if (!deletedDevice) {
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }
    res.status(200).json({ message: 'Dispositivo deletado com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao deletar dispositivo' });
  }
});

// ==================
// Rotas de Leituras
// ==================

// Adicionar leitura de sensor
app.post('/api/readings', authenticateToken, async (req, res) => {
  const { deviceId, temperature, humidity, gasLevel } = req.body;
  const newReading = new Reading({ deviceId, temperature, humidity, gasLevel });

  try {
    const savedReading = await newReading.save();
    res.status(201).json(savedReading);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao salvar leitura' });
  }
});

// Listar leituras de um dispositivo
app.get('/api/readings/:deviceId', authenticateToken, async (req, res) => {
  const { deviceId } = req.params;

  try {
    const readings = await Reading.find({ deviceId });
    res.json(readings);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar leituras' });
  }
});

// ==================
// Inicialização do Servidor
// ==================
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
