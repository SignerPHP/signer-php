<?php

declare(strict_types=1);

namespace SignerPHP\Infrastructure\PdfCore\Service;

use SignerPHP\Infrastructure\PdfCore\Contract\SignatureRuntimeInterface;

final class NativeSignatureRuntime implements SignatureRuntimeInterface
{
    private ?bool $supportsNoSigningTime = null;

    public function __construct(
        private readonly string $opensslBinary = 'openssl',
    ) {}

    public function fileSize(string $path): int|false
    {
        return filesize($path);
    }

    public function createTempFile(string $directory, string $prefix): string|false
    {
        return tempnam($directory, $prefix);
    }

    public function signPkcs7(string $inputFile, string $outputFile, string $certificate, string $privateKey): bool
    {
        return openssl_pkcs7_sign($inputFile, $outputFile, $certificate, $privateKey, [], PKCS7_BINARY | PKCS7_DETACHED);
    }

    public function signCadesDetached(string $inputFile, string $outputFile, string $certificate, string $privateKey): bool
    {
        $certificateFile = tempnam(sys_get_temp_dir(), 'pdfcert');
        $privateKeyFile = tempnam(sys_get_temp_dir(), 'pdfkey');
        if ($certificateFile === false || $privateKeyFile === false) {
            if (is_string($certificateFile)) {
                @unlink($certificateFile);
            }

            if (is_string($privateKeyFile)) {
                @unlink($privateKeyFile);
            }

            return false;
        }

        try {
            if (
                file_put_contents($certificateFile, $certificate) === false
                || file_put_contents($privateKeyFile, $privateKey) === false
            ) {
                return false;
            }

            $command = [
                $this->opensslBinary,
                'cms',
                '-sign',
                '-in',
                $inputFile,
                '-signer',
                $certificateFile,
                '-inkey',
                $privateKeyFile,
                '-binary',
                '-cades',
                '-nosmimecap',
                '-md',
                'sha256',
                '-outform',
                'DER',
                '-out',
                $outputFile,
            ];

            if ($this->opensslSupportsNoSigningTime()) {
                $command[] = '-no_signing_time';
            }

            return $this->runCommand($command);
        } finally {
            @unlink($certificateFile);
            @unlink($privateKeyFile);
        }
    }

    public function readFile(string $path): string|false
    {
        return file_get_contents($path);
    }

    public function removeFile(string $path): void
    {
        @unlink($path);
    }

    private function opensslSupportsNoSigningTime(): bool
    {
        if ($this->supportsNoSigningTime !== null) {
            return $this->supportsNoSigningTime;
        }

        $pipes = [];
        $process = proc_open(
            [$this->opensslBinary, 'cms', '-sign', '-help'],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        if (! is_resource($process)) {
            return $this->supportsNoSigningTime = false;
        }

        fclose($pipes[0]);
        $help = (string) stream_get_contents($pipes[1]).(string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        return $this->supportsNoSigningTime = str_contains($help, 'no_signing_time');
    }

    /**
     * @param  array<int, string>  $command
     */
    private function runCommand(array $command): bool
    {
        $pipes = [];
        $process = proc_open(
            $command,
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        if (! is_resource($process)) {
            return false;
        }

        fclose($pipes[0]);
        stream_get_contents($pipes[1]);
        stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return proc_close($process) === 0;
    }

    public function isFile(string $path): bool
    {
        return is_file($path);
    }

    public function decodeBase64(string $value): string|false
    {
        return base64_decode($value, true);
    }

    public function toHex(string $binary): string
    {
        return bin2hex($binary);
    }
}
