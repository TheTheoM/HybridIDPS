import React from 'react';

export default function Cross(props) {
  const svgStyle = {
    filter: 'drop-shadow(0 0 5px red)', // Add a red shadow
  };

  return (
    <div className='crossDropShadow'>
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="2em"
        height="2em"
        viewBox="0 0 24 24"
        {...props}
      >
        <path
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeWidth="2"
          d="M20 20L4 4m16 0L4 20"
        ></path>
      </svg>
    </div>
  );
}
