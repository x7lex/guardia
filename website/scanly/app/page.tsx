'use client'
import {useState} from 'react'
import Image from "next/image";
import Button from "@/components/button"
import Banner from "@/components/banner"
import Form from "@/components/Form"

export default function Home() {
    const [input, setInput] = useState("");
    const [directory, setDirectory] = useState<string>("");
  return (
    <div className="min-h-screen w-screen">
        <Banner/>
        <div className='flex-col '>
            <div className='flex justify-center'>
                <Form>
                    <label>Enter The Directory To Your File</label>
                    <div className={'flex inline-block p-[1px] rounded-[3px] rounded-bl-[10px_20px] rounded-tl-[10px_20px] rounded-br-[10px_20px] rounded-tr-[10px_20px] border border-[#ffbf9b] border-2 drop-shadow-[0px_4px_4px_#634c53]'}>
                        <input type = "text" placeholder = "Enter File Path" value = {input} onChange = {(e) => setInput(e.target.value)} onKeyDown={(e) => {if (e.key === "Enter") {setDirectory(input);}}} className={'py-2 px-5 border border-[#FFBBBA] border-2 rounded-[3px] rounded-bl-[7px_17px] rounded-tl-[7px_17px] rounded-br-[7px_17px] rounded-tr-[7px_17px] bg-linear-to-t from-[#FFBBBA] to-[#FFF2CC] hover:bg-none hover:bg-[#FFBBBA] hover:cursor-pointer active:scale-[110%]'}/>
                    </div>
                </Form>
            </div>
        </div>
    </div>
  );
}
