"""
Main Flask application for quantum cryptography comparison demo.
"""
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room
import secrets
from crypto.rsa_crypto import RSACrypto
from crypto.kyber_crypto import KyberCrypto
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Constants
MIN_RSA_KEY_SIZE = 128
DEFAULT_RSA_KEY_SIZE = 2048

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    logger=True,
    engineio_logger=True,
    ping_timeout=60,
    ping_interval=25,
    async_mode='threading'
)

# Store room data
rooms = {}

@app.route('/')
def index():
    """Render the main chat interface."""
    return render_template('index.html')

@app.route('/attacker')
def attacker():
    """Render the attacker's view."""
    return render_template('attacker.html')

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    logger.debug(f'Client connected: {request.sid}')
    emit('connect', {'sid': request.sid})

@socketio.on('message')
def handle_message(data):
    """Handle incoming chat messages"""
    try:
        room = data.get('room')
        message = data.get('message', '').strip()
        
        if not room or room not in rooms:
            emit('error', {'message': 'Invalid room', 'recoverable': True}, room=request.sid)
            return

        room_data = rooms[room]
        sender = next((user for user in room_data['users'] if user['sid'] == request.sid), None)
        if not sender:
            emit('error', {'message': 'User not found in room', 'recoverable': True}, room=request.sid)
            return

        if not message:
            emit('error', {'message': 'Empty message', 'recoverable': True}, room=request.sid)
            return

        # Get crypto instance
        crypto = room_data['crypto']

        # Send message to sender (their own message)
        emit('message', {
            'sender': sender['username'],
            'message': message,
            'is_self': True
        }, room=request.sid)

        # Handle encryption and sending to other users
        for recipient in room_data['users']:
            if recipient['sid'] != request.sid:  # Don't send to self
                try:
                    # Encrypt message for recipient
                    encrypted = crypto.encrypt(message, recipient['public_key'])
                    
                    # Send message to recipient with both original and encrypted
                    emit('message', {
                        'sender': sender['username'],
                        'message': message,
                        'encrypted': encrypted,
                        'is_self': False
                    }, room=recipient['sid'])
                    
                except Exception as e:
                    logger.error(f"Encryption error: {str(e)}")
                    emit('error', {
                        'message': f'Failed to encrypt message: {str(e)}',
                        'recoverable': True
                    }, room=recipient['sid'])
            
    except Exception as e:
        logger.error(f"Message handling error: {str(e)}")
        emit('error', {
            'message': f'Error processing message: {str(e)}',
            'recoverable': True
        }, room=request.sid)

@socketio.on('error')
def handle_error(error):
    """Handle errors without disconnecting the client"""
    try:
        logger.error(f"Client error: {error}")
        emit('error', {
            'message': str(error),
            'recoverable': True
        }, room=request.sid)
    except Exception as e:
        logger.error(f"Error handling error: {str(e)}")

@socketio.on_error_default
def default_error_handler(e):
    """Default error handler to prevent disconnections"""
    logger.error(f"Unhandled error: {str(e)}")
    emit('error', {
        'message': 'An unexpected error occurred',
        'recoverable': True
    }, room=request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    try:
        # Find and remove user from their room
        for room_name, room_data in list(rooms.items()):
            user = next((user for user in room_data['users'] if user['sid'] == request.sid), None)
            if user:
                room_data['users'].remove(user)
                emit('user_left', {'username': user['username']}, room=room_name)
                
                # If room is empty, clean it up
                if not room_data['users']:
                    del rooms[room_name]
                break
                
    except Exception as e:
        logger.error(f"Error handling disconnect: {str(e)}")

@socketio.on('join')
def on_join(data):
    """Handle user joining a room"""
    try:
        username = data.get('username', '').strip()
        room = data.get('room', '').strip()
        encryption_type = data.get('encryption_type', '')
        key_size = data.get('key_size', '')
        kyber_mode = data.get('kyber_mode', 'simulated')
        
        logger.info(f"Join request: {username=}, {room=}, {encryption_type=}, {key_size=}, {kyber_mode=}")
        
        if not username or not room:
            raise ValueError("Username and room are required")
        
        # Convert key_size to int for RSA
        if encryption_type == 'rsa':
            try:
                key_size = int(key_size)
            except (ValueError, TypeError):
                raise ValueError(f"Invalid RSA key size: {key_size}")
        
        # Create or get room
        if room not in rooms:
            try:
                # Initialize crypto based on type
                if encryption_type == 'kyber':
                    crypto = KyberCrypto(mode=kyber_mode)
                else:
                    crypto = RSACrypto(key_size=key_size)
                
                rooms[room] = {
                    'users': [],
                    'crypto': crypto,
                    'encryption_type': encryption_type,
                    'key_size': key_size,
                    'kyber_mode': kyber_mode
                }
                logger.info(f"Created new room: {room}")
                
            except Exception as e:
                logger.error(f"Failed to initialize encryption: {str(e)}")
                emit('error', {'message': f'Failed to initialize encryption: {str(e)}'})
                return
                
        else:
            # Verify encryption settings match
            room_data = rooms[room]
            if room_data['encryption_type'] != encryption_type:
                emit('error', {'message': f"Room is using {room_data['encryption_type']} encryption"})
                return
            if encryption_type == 'rsa' and room_data['key_size'] != key_size:
                emit('error', {'message': f"Room is using {room_data['key_size']}-bit RSA keys"})
                return
            if encryption_type == 'kyber' and room_data['kyber_mode'] != kyber_mode:
                emit('error', {'message': f"Room is using {room_data['kyber_mode']} Kyber mode"})
                return
        
        # Add user to room
        join_room(room)
        
        # Get crypto instance and generate keys
        crypto = rooms[room]['crypto']
        try:
            if encryption_type == 'kyber':
                public_key = crypto.get_public_key_base64()
            else:
                public_key = crypto.get_public_key_pem()
        except Exception as e:
            logger.error(f"Failed to generate keys: {str(e)}")
            leave_room(room)
            emit('error', {'message': f'Failed to generate keys: {str(e)}'})
            return
        
        # Add user data
        user_data = {
            'username': username,
            'sid': request.sid,
            'public_key': public_key
        }
        rooms[room]['users'].append(user_data)
        
        # Notify room of new user
        emit('user_joined', {
            'username': username,
            'public_key': public_key,
            'encryption_type': encryption_type,
            'key_size': key_size,
            'kyber_mode': kyber_mode if encryption_type == 'kyber' else None
        }, room=room)
        
        # Send existing users to new user
        for existing_user in rooms[room]['users']:
            if existing_user['sid'] != request.sid:
                emit('user_joined', {
                    'username': existing_user['username'],
                    'public_key': existing_user['public_key'],
                    'encryption_type': encryption_type,
                    'key_size': key_size,
                    'kyber_mode': kyber_mode if encryption_type == 'kyber' else None
                }, room=request.sid)
        
        logger.info(f"User {username} joined room {room}")
        
    except Exception as e:
        logger.error(f"Error in join handler: {str(e)}")
        emit('error', {'message': str(e)})

@socketio.on('send_message')
def on_message(data):
    """Handle sending encrypted messages."""
    try:
        sender = data.get('sender')
        room = data.get('room')
        message = data.get('message')
        recipient_key = data.get('recipient_key')
        
        if not all([sender, room, message, recipient_key]):
            raise ValueError("Missing required message data")
        
        logger.debug(f'Message from {sender} in room {room}')
        
        if room not in rooms:
            raise ValueError('Room does not exist')
        
        room_data = rooms[room]
        sender_data = room_data['users'].get(request.sid)
        
        if not sender_data:
            raise ValueError('Sender not found in room')
        
        # Encrypt message using recipient's public key
        encrypted_message = sender_data['crypto'].encrypt(message, recipient_key)
        
        if not encrypted_message:
            raise ValueError('Failed to encrypt message')
        
        # Send to all users in the room except sender
        for recipient_sid, recipient_data in room_data['users'].items():
            if recipient_sid != request.sid:
                try:
                    # Decrypt message for verification
                    decrypted_message = recipient_data['crypto'].decrypt(encrypted_message)
                    
                    # Send both encrypted and decrypted message
                    emit('new_message', {
                        'sender': sender,
                        'encrypted_message': encrypted_message,
                        'decrypted_message': decrypted_message
                    }, room=recipient_sid)
                    
                    logger.debug(f'Message sent from {sender} to {recipient_data["username"]}')
                    
                except Exception as e:
                    logger.error(f'Error processing message: {str(e)}')
                    emit('error', {
                        'message': f'Failed to process message: {str(e)}'
                    }, room=recipient_sid)
                    
    except Exception as e:
        logger.error(f'Error sending message: {str(e)}')
        emit('error', {'message': str(e)}, room=request.sid)

@socketio.on('breach_attempt')
def on_breach_attempt(data):
    try:
        # Extract required data
        room = data.get('room')
        public_key = data.get('public_key')
        encrypted_message = data.get('encrypted_message')
        encryption_type = data.get('encryption_type')
        
        # Validate required data
        if not all([room, public_key, encrypted_message, encryption_type]):
            app.logger.error(f"Missing required data for breach attempt: {data}")
            return
        
        app.logger.debug(f"Breach attempt received for room {room}")
        app.logger.debug(f"Public key length: {len(public_key)}")
        app.logger.debug(f"Encrypted message length: {len(encrypted_message)}")
        app.logger.debug(f"Encryption type: {encryption_type}")
        
        # Parse encryption type and key size
        enc_type, key_size = encryption_type.split('-')
        key_size = int(key_size)
        
        # Define progress callback for tiny RSA
        def progress_callback(attempt, current_d, decrypted, valid):
            socketio.emit('decryption_progress', {
                'attempt': attempt,
                'current_d': current_d,
                'decrypted': decrypted,
                'valid': valid
            })
        
        # Handle breach attempt based on encryption type
        if enc_type == 'rsa':
            # Create RSA crypto object with specified key size
            rsa = RSACrypto(key_size=key_size)
            
            # Attempt breach with progress callback for tiny RSA
            result = rsa.simulate_brute_force(
                public_key=public_key,
                encrypted_message=encrypted_message,
                progress_callback=progress_callback if key_size <= 16 else None
            )
            
            # Emit result with show_progress flag for tiny RSA
            socketio.emit('breach_result', {
                'success': result['success'],
                'encryption_type': f'RSA-{key_size}',
                'time_taken': f"{result['time_taken']:.2f} seconds",
                'decrypted_message': result['decrypted_message'],
                'notes': result['notes'],
                'show_progress': key_size <= 16
            })
            
        elif enc_type == 'kyber':
            # Kyber is quantum-resistant, always return failure
            socketio.emit('breach_result', {
                'success': False,
                'encryption_type': f'Kyber-{key_size}',
                'time_taken': '0.00 seconds',
                'decrypted_message': None,
                'notes': 'Kyber is quantum-resistant and cannot be broken by known attacks.',
                'show_progress': False
            })
            
    except Exception as e:
        app.logger.error(f"Error during breach attempt: {str(e)}")
        app.logger.exception(e)
        socketio.emit('breach_result', {
            'success': False,
            'encryption_type': encryption_type,
            'time_taken': '0.00 seconds',
            'decrypted_message': None,
            'notes': f'Error during breach attempt: {str(e)}',
            'show_progress': False
        })

if __name__ == '__main__':
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=True,
        allow_unsafe_werkzeug=True  # Required for development
    ) 