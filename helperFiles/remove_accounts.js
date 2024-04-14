const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, '..', 'innerLayer', 'registeredUsers.json');

const keepUsers = new Set(['JohnSmith123', 'Jane', 'admin']);

fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
        console.error('Error reading the file:', err);
        return;
    }

    let users = JSON.parse(data);

    users = users.filter(([username, _]) => keepUsers.has(username));

    const updatedData = JSON.stringify(users, null, 2);

    fs.writeFile(filePath, updatedData, 'utf8', (err) => {
        if (err) {
            console.error('Error writing the file:', err);
        } else {
            console.log('File updated successfully!');
        }
    });
});
