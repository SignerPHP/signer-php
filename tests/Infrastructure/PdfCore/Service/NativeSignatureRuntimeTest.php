<?php

declare(strict_types=1);

namespace SignerPHP\Tests\Infrastructure\PdfCore\Service;

use PHPUnit\Framework\TestCase;
use SignerPHP\Infrastructure\PdfCore\Service\NativeSignatureRuntime;
use SignerPHP\Infrastructure\PdfCore\Service\PdfCoreSignatureRuntimeOverrideState;

final class NativeSignatureRuntimeTest extends TestCase
{
    /** @var array<int, string> */
    private array $temporaryDirectories = [];

    protected function tearDown(): void
    {
        PdfCoreSignatureRuntimeOverrideState::$forceTempnamFailure = false;
        PdfCoreSignatureRuntimeOverrideState::$forceProcOpenFailure = false;
        PdfCoreSignatureRuntimeOverrideState::$forceFilePutContentsFailure = false;
        PdfCoreSignatureRuntimeOverrideState::$failTempnamPrefixes = [];

        foreach ($this->temporaryDirectories as $directory) {
            $files = glob($directory.'/*') ?: [];
            foreach ($files as $file) {
                if (is_file($file)) {
                    @unlink($file);
                }
            }

            @rmdir($directory);
        }

        $this->temporaryDirectories = [];

        parent::tearDown();
    }

    public function test_sign_cades_detached_runs_openssl_cms_with_ess_and_no_signing_time(): void
    {
        $binary = $this->makeOpenSslStub(true);
        $output = sys_get_temp_dir().'/signed-'.bin2hex(random_bytes(6)).'.der';

        $runtime = new NativeSignatureRuntime($binary);

        self::assertTrue($runtime->signCadesDetached('/tmp/input.pdf', $output, 'CERT', 'KEY'));
        self::assertSame('DER-CMS', file_get_contents($output));
        @unlink($output);

        $args = (string) file_get_contents(dirname($binary).'/args.log');
        self::assertStringContainsString('cms -sign', $args);
        self::assertStringContainsString('-binary', $args);
        self::assertStringContainsString('-cades', $args);
        self::assertStringContainsString('-nosmimecap', $args);
        self::assertStringContainsString('-md sha256', $args);
        self::assertStringContainsString('-outform DER', $args);
        self::assertStringContainsString('-no_signing_time', $args);
        self::assertStringContainsString('-signer', $args);
        self::assertStringContainsString('-inkey', $args);
    }

    public function test_sign_cades_detached_omits_no_signing_time_when_openssl_does_not_support_it(): void
    {
        $binary = $this->makeOpenSslStub(false);
        $output = sys_get_temp_dir().'/signed-'.bin2hex(random_bytes(6)).'.der';

        $runtime = new NativeSignatureRuntime($binary);

        self::assertTrue($runtime->signCadesDetached('/tmp/input.pdf', $output, 'CERT', 'KEY'));
        @unlink($output);

        $args = (string) file_get_contents(dirname($binary).'/args.log');
        self::assertStringContainsString('-cades', $args);
        self::assertStringNotContainsString('no_signing_time', $args);
    }

    public function test_sign_cades_detached_probes_openssl_help_only_once(): void
    {
        $binary = $this->makeOpenSslStub(true);
        $firstOutput = sys_get_temp_dir().'/signed-'.bin2hex(random_bytes(6)).'.der';
        $secondOutput = sys_get_temp_dir().'/signed-'.bin2hex(random_bytes(6)).'.der';

        $runtime = new NativeSignatureRuntime($binary);

        self::assertTrue($runtime->signCadesDetached('/tmp/input.pdf', $firstOutput, 'CERT', 'KEY'));
        self::assertTrue($runtime->signCadesDetached('/tmp/input.pdf', $secondOutput, 'CERT', 'KEY'));
        @unlink($firstOutput);
        @unlink($secondOutput);

        $args = (string) file_get_contents(dirname($binary).'/args.log');
        self::assertSame(1, substr_count($args, '-help'));
        self::assertSame(2, substr_count($args, '-cades'));
    }

    public function test_sign_cades_detached_returns_false_when_openssl_fails(): void
    {
        $binary = $this->makeOpenSslStub(true, 3);
        $output = sys_get_temp_dir().'/signed-'.bin2hex(random_bytes(6)).'.der';

        $runtime = new NativeSignatureRuntime($binary);

        self::assertFalse($runtime->signCadesDetached('/tmp/input.pdf', $output, 'CERT', 'KEY'));
    }

    public function test_sign_cades_detached_returns_false_when_temp_files_cannot_be_created(): void
    {
        PdfCoreSignatureRuntimeOverrideState::$forceTempnamFailure = true;

        $runtime = new NativeSignatureRuntime('/tmp/does-not-exist-openssl');

        self::assertFalse($runtime->signCadesDetached('/tmp/input.pdf', '/tmp/output.der', 'CERT', 'KEY'));
    }

    public function test_sign_cades_detached_returns_false_when_private_key_temp_file_cannot_be_created(): void
    {
        PdfCoreSignatureRuntimeOverrideState::$failTempnamPrefixes = ['pdfkey'];

        $runtime = new NativeSignatureRuntime('/tmp/does-not-exist-openssl');

        self::assertFalse($runtime->signCadesDetached('/tmp/input.pdf', '/tmp/output.der', 'CERT', 'KEY'));
    }

    public function test_sign_cades_detached_returns_false_when_certificate_material_cannot_be_written(): void
    {
        PdfCoreSignatureRuntimeOverrideState::$forceFilePutContentsFailure = true;

        $runtime = new NativeSignatureRuntime('/tmp/does-not-exist-openssl');

        self::assertFalse($runtime->signCadesDetached('/tmp/input.pdf', '/tmp/output.der', 'CERT', 'KEY'));
    }

    public function test_sign_cades_detached_returns_false_when_process_cannot_be_started(): void
    {
        PdfCoreSignatureRuntimeOverrideState::$forceProcOpenFailure = true;

        $runtime = new NativeSignatureRuntime('/tmp/does-not-exist-openssl');

        self::assertFalse($runtime->signCadesDetached('/tmp/input.pdf', '/tmp/output.der', 'CERT', 'KEY'));
    }

    private function makeOpenSslStub(bool $advertisesNoSigningTime, int $exitCode = 0): string
    {
        $directory = sys_get_temp_dir().'/signer-runtime-'.bin2hex(random_bytes(6));
        mkdir($directory, 0777, true);
        $this->temporaryDirectories[] = $directory;

        $helpLine = $advertisesNoSigningTime
            ? '-no_signing_time         Omit the signing time attribute'
            : '-nosmimecap              Omit the SMIMECapabilities attribute';

        $script = "#!/usr/bin/env bash\n"
            .'printf \'%s\\n\' "$*" >> "'.$directory.'/args.log"'."\n"
            .'if [[ "$*" == *"-help"* ]]; then'."\n"
            .'    echo "Usage: cms -sign '.$helpLine.'"'."\n"
            .'    exit 0'."\n"
            .'fi'."\n"
            .'out=""'."\n"
            .'prev=""'."\n"
            .'for arg in "$@"; do'."\n"
            .'    if [ "$prev" = "-out" ]; then out="$arg"; fi'."\n"
            .'    prev="$arg"'."\n"
            .'done'."\n"
            .'if [ -n "$out" ]; then printf \'DER-CMS\' > "$out"; fi'."\n"
            .'exit '.$exitCode."\n";

        $binary = $directory.'/openssl';
        file_put_contents($binary, $script);
        chmod($binary, 0755);

        return $binary;
    }
}
