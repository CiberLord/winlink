import { createInterface } from 'node:readline/promises'
import { certificateCode, discoverCertificate, register, saveProfile, type Profile } from './transport.js'

export async function pair(file: string, address: string): Promise<Profile> {
    if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('Run winlink pair in an interactive Mac terminal.')
    const certificate = await discoverCertificate(address)
    const terminal = createInterface({ input: process.stdin, output: process.stdout })
    try {
        console.log(`Windows certificate code: ${certificateCode(certificate)}`)
        const answer = await terminal.question('Does the Windows certificate code match? [y/N] ')
        if (!/^y(es)?$/i.test(answer.trim())) throw new Error('Pairing cancelled.')
        const pin = await terminal.question('Windows pairing PIN (8 digits): ')
        const profile = await register({ address, certificate }, pin.trim())
        await saveProfile(file, profile)
        return profile
    } finally {
        terminal.close()
    }
}
