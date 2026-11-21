#!/usr/bin/env node
import { access, appendFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { parseArgs } from 'node:util'
import { pair } from './pair.js'
import { download, list, powershell, prepareHome, probe, upload } from './ssh.js'

const home = path.resolve(process.env.WINLINK_HOME ?? path.join(os.homedir(), '.winlink'))
const config = path.join(home, 'ssh_config')
const help = `Usage: winlink <command>

  pair [--ip MAC_IP]                     Pair a Windows PC
  doctor [--json]                       Check TCP, SSH, PowerShell and SFTP
  exec [--json] '<PowerShell>'          Run a PowerShell command
  ls [--json] [WINDOWS_DIR]             List a directory (default: SSH working directory)
  get [--json] WINDOWS_FILE MAC_FILE    Download a file
  put [--json] MAC_FILE WINDOWS_FILE    Upload a file

Remote commands accept --timeout SECONDS (default: 60).
Use absolute Windows paths, for example 'C:\\Mods\\example.zip'.`

async function main() {
    const [command, ...args] = process.argv.slice(2)
    if (!command || ['help', '--help', '-h'].includes(command) || args.includes('--help')) {
        console.log(help)
        return
    }

    if (command === 'pair') {
        const { values } = parseArgs({ args, options: { ip: { type: 'string' } } })
        await prepareHome(home)
        const profile = await pair(home, values.ip)
        console.log(`Connected to ${profile.address} as ${profile.user}. SSH, PowerShell and SFTP passed.`)
        return
    }

    const { values, positionals } = parseArgs({
        args, allowPositionals: true,
        options: { json: { type: 'boolean' }, timeout: { type: 'string' } },
    })
    const timeout = Number(values.timeout ?? 60)
    const counts: Record<string, number[]> = { doctor: [0], exec: [1], ls: [0, 1], get: [2], put: [2] }
    let success = false
    try {
        if (!Object.hasOwn(counts, command) || !counts[command].includes(positionals.length)
            || !Number.isInteger(timeout) || timeout < 1 || timeout > 3600) {
            throw new Error('Invalid command, arguments or timeout. See winlink --help.')
        }
        await access(config).catch(() => { throw new Error('No active profile. Run winlink pair on the Mac first.') })
        let result: unknown
        let exit = 0
        if (command === 'exec') {
            const execution = await powershell(config, positionals[0], timeout)
            result = execution
            exit = execution.timedOut ? 124 : execution.exitCode
            if (!values.json) {
                process.stdout.write(execution.stdout)
                process.stderr.write(execution.stderr)
                if (execution.timedOut) process.stderr.write('PowerShell command timed out.\n')
            }
        } else if (command === 'doctor') {
            const report = await probe(config, timeout)
            result = report
            exit = report.ok ? 0 : 1
        } else if (command === 'ls') {
            result = await list(config, positionals[0] ?? '.', timeout)
        } else {
            await (command === 'get' ? download : upload)(config, positionals[0], positionals[1], timeout)
            result = { destination: positionals[1] }
        }
        success = exit === 0
        if (values.json) console.log(JSON.stringify({ version: 1, ok: success, result }))
        else if (command !== 'exec') console.log(JSON.stringify(result, null, 2))
        process.exitCode = exit
    } catch (error) {
        const message = (error as Error).message
        if (values.json) console.log(JSON.stringify({ version: 1, ok: false, error: message }))
        else console.error(`winlink: ${message}`)
        process.exitCode = 1
    } finally {
        if (Object.hasOwn(counts, command)) {
            await appendFile(path.join(home, 'operations.jsonl'),
                JSON.stringify({ time: new Date().toISOString(), command, ok: success }) + '\n', { mode: 0o600 })
                .catch(error => {
                    if (error.code !== 'ENOENT') console.error('winlink: could not write the operation log.')
                })
        }
    }
}

main().catch(error => {
    console.error(`winlink: ${error.message}`)
    process.exitCode = 1
})
