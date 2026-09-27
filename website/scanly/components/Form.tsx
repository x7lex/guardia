import React from 'react'

interface props {
    children?: React.ReactNode
}

export default function Form({ children }: props) {
    return (
        <div className='border-2 bg-[#ffebd7] w-100 h-120 mt-5 flex items-center justify-center'>
            {children}
        </div>
    )
}