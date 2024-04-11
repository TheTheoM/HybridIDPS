import React, { useState, useEffect, useRef } from 'react';

const BanWindow = () => {

    useEffect(() => {
        localStorage.removeItem('credentials');
    }, [])


    return (
        <div className='container'>
            <div className='banWindow'>
                <h1 style={{'color': "red"}}>Banned</h1>
                <h3>Your IP has been logged.</h3>
                <h3> Any further attempts to access this platform will trigger immediate notification of law enforcement authorities, leading to potential legal consequences.</h3>
            </div>
        </div>
    );
};

export default BanWindow;
