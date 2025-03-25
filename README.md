# Quantum Cryptography Comparison

A web-based demonstration and comparison of different quantum-resistant cryptographic algorithms.

## Features

- Real-time chat interface with encryption
- Multiple cryptographic algorithms:
  - RSA (Traditional)
  - NTRU (Post-Quantum)
  - Kyber (Post-Quantum)
- Secure key management system
- Attacker simulation interface
- WebSocket-based real-time communication

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd quantum_crypto_comparison
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Application

1. Start the Flask application:
```bash
python src/app.py
```

2. Open your browser and navigate to:
- Main interface: http://localhost:5000
- Attacker interface: http://localhost:5000/attacker

## Project Structure

```
quantum_crypto_comparison/
├── src/
│   ├── app.py              # Main Flask application
│   ├── crypto/             # Cryptographic implementations
│   │   ├── rsa_crypto.py   # RSA implementation
│   │   ├── ntru_crypto.py  # NTRU implementation
│   │   └── key_manager.py  # Key management system
│   └── templates/          # HTML templates
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## Technologies Used

- Backend: Python, Flask, SocketIO
- Frontend: HTML, JavaScript
- Cryptography: RSA, NTRU, Kyber
- Real-time Communication: WebSocket

## Security Considerations

- All cryptographic operations are performed using well-established libraries
- Secure key generation and management
- Real-time communication is encrypted
- Includes security testing features

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Thanks to the cryptography community for their libraries and implementations
- Special thanks to the developers of the post-quantum cryptographic algorithms