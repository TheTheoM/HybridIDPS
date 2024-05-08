const WebSocket = require('ws');

for (let i = 0; i < 9; i++) {
    class WebSocketClient {
        constructor(url) {
            this.url = url;
            this.socket = new WebSocket(url);
    
            this.socket.on('open', () => {
                console.log('WebSocket connection established.');
            });
    
            this.socket.on('message', (data) => {
                const message = JSON.parse(data);
    
                console.log('Message received from server:', message);
                if (message.action === 'checkRegistration') {
                    this.send({ action: 'register', username: 'example_user' + i, password: 'example_password', email: 'example@example.com' });
                }
    
                if (message.action === 'registrationSuccess') {
                    this.send({ action: 'login', username: 'example_user' + i, password: 'example_password'});
                }

                if (message.action === 'viewFeedAndUser') {
                    // Assuming loginSuccess event carries the username
                    this.send({ action: 'reportUserByUsername', username: 'JohnSmith123'});
                }
    

                // this.send({action: 'reportUserByUsername', username: 'JohnSmith123'})
    
    
    
            });
    
            this.socket.on('close', () => {
                console.log('WebSocket connection closed.');
            });
    
            this.socket.on('error', (error) => {
                console.error('WebSocket error:', error);
            });
        }
    
        send(data) {
            this.socket.send(JSON.stringify(data));
            console.log('Message sent to server:', data);
        }
    }
    
    const client = new WebSocketClient('ws://localhost:8100'); // Replace with your WebSocket server address
}