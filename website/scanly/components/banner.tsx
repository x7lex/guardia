import Link from "next/link";

export default function Banner(){
    return(
        <div className = "flex items-center border w-full h-20 px-3 bg-[url('/checkers_bg.png')] bg-repeat bg-[length:200px_100px]">
            <Link href = "/" className="contents">
                <img src = "/banner.png" alt="scanly banner" className = " h-[80%] border-2 border-[color:#9D7E67] [border-style:inset]"/>
            </Link>
            <h1 className = "text-blue-600">Scanly Opsec Demons</h1>
        </div>
    )
}  