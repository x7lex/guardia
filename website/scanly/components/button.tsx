import React from "react"

interface props {
    children?: React.ReactNode,
    className?: string,
    onClick?: () => any
}

export default function Button({ children, className, onClick }: props) {

    return (
        <div className={'inline-block p-[1px] rounded-[3px] rounded-bl-[10px_20px] rounded-tl-[10px_20px] rounded-br-[10px_20px] rounded-tr-[10px_20px] border border-[#ffbf9b] border-2 drop-shadow-[0px_4px_4px_#634c53] ' + className}>
            <button onClick={onClick} className={'py-2 px-15 border border-[#FFBBBA] border-2 rounded-[3px] rounded-bl-[7px_17px] rounded-tl-[7px_17px] rounded-br-[7px_17px] rounded-tr-[7px_17px] bg-linear-to-t from-[#FFBBBA] to-[#FFF2CC]'}>
                {children}
            </button>
        </div>

    )
}