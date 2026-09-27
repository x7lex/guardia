import Button from "@/components/button"


interface props {
    paths: string[],
    className?: string
}

function sendPath() {

}

export default function Analysis({ paths, className }: props) {
    return (
        <>
            {paths}
            <Button onClick={sendPath}>Scan</Button>

        </>
    )
}