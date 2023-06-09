# Cara Menjalankan
- Clone <i>repository</i> ini ke perangkat lokal
- Buka direktori hasil <i>clone</i> dari <i>repository</i> ini dengan Android Studio
- Tunggu sampai Android Studio selesai melakukan <i>setup</i> dan <i>indexing</i>
- Jalankan program dengan <i>run configuration</i> <b>app.k9mail</b> pada perangkat virtual atau fisik

# Cara Menggunakan
## Membangkitkan Private Key dan Public Key
- Tarik <i> navigation drawer</i> pada sebelah kiri layar
- Tekan tombol "Generate Key"
- Aplikasi akan menampilkan satu buah <i>private key</i> dan dua buah <i>public key</i>, kunci-kunci ini dapat di-<i>copy</i> dengan cara memblok (menekan lama) tulisan pada kunci-kunci tersebut

## Melakukan Enkripsi Pesan
- Buat pesan baru dengan menekan tombol dengan lambang pensil pada ujung kanan bawah layar
- Tekan tombol <i>options</i> pada bagian kanan atas layar (tombol dengan lambang 3 titik yang tersusun vertikal)
- Pilih "Encrypt Message"
- Masukkan kunci enkripsi (jika kunci enkripsi tidak valid, aplikasi akan memberi peringatan)
- Saat dikirim pesan akan dienkripsi dengan menggunakan kunci yang sudah diberikan
- Untuk membatalkan pengenkripsian sebelum dikirm, tekan tombol <i>options</i> pada bagian kanan atas layar (tombol dengan lambang 3 titik yang tersusun vertikal) dan pilih "Don't Encrypt Message"

## Melakukan Tanda Tangan Pada Pesan
- Buat pesan baru dengan menekan tombol dengan lambang pensil pada ujung kanan bawah layar
- Tekan tombol <i>options</i> pada bagian kanan atas layar (tombol dengan lambang 3 titik yang tersusun vertikal)
- Pilih "Sign Message"
- Masukkan kunci privat (jika kunci privat tidak valid, aplikasi akan memberi peringatan)
- Saat dikirim pesan akan ditandatangani dengan menggunakan kunci privat yang sudah diberikan
- Untuk membatalkan penandatanganan sebelum dikirm, tekan tombol <i>options</i> pada bagian kanan atas layar (tombol dengan lambang 3 titik yang tersusun vertikal) dan pilih "Don't Sign Message"

<strong>Enkripsi dan Tanda Tangan dapat dilakukan bersamaan, yang dilakukan pertama adalah tanda tangan lalu selanjutnya enkripsi.</strong>

## Melakukan Dekripsi Pesan
- Pilih salah satu <i>email</i> pada <i>inbox</i>, surat terkirim, atau spam
- Tekan tombol <i>options</i> pada bagian kanan atas layar (tombol dengan lambang 3 titik yang tersusun vertikal)
- Pilih "Process message"
- Pengguna akan dialihkan ke suatu halaman yang dapat digunakan juga untuk mengirim pesan hasil proses atau menyimpan sebagai draf untuk memudahkan pengguna
- Tekan tombol <i>options</i> pada bagian kanan atas layar (tombol dengan lambang 3 titik yang tersusun vertikal)
- Pilih "Decrypt Message"
- Masukkan kunci dekripsi (jika kunci dekripsi tidak valid, aplikasi akan memberi peringatan)
- Pesan akan ditampilkan dalam bentuk setelah didekripsi

## Melakukan Verifikasi Tanda Tangan Pesan
- Pilih salah satu <i>email</i> pada <i>inbox</i>, surat terkirim, atau spam
- Tekan tombol <i>options</i> pada bagian kanan atas layar (tombol dengan lambang 3 titik yang tersusun vertikal)
- Pilih "Process message"
- Pengguna akan dialihkan ke suatu halaman yang dapat digunakan juga untuk mengirim pesan hasil proses atau menyimpan sebagai draf untuk memudahkan pengguna
- Tekan tombol <i>options</i> pada bagian kanan atas layar (tombol dengan lambang 3 titik yang tersusun vertikal)
- Pilih "Verify Sign Message"
- Masukkan kedua dengan kunci publik dengan cara meng-<i>append</i> kedua kunci tersebut (jika kunci publik tidak valid, aplikasi akan memberi peringatan)
- Aplikasi akan memberikan <i>alert</i> pesan terverifikasi atau tidak

# K-9 Mail

[![Latest release](https://img.shields.io/github/release/thundernest/k-9.svg?style=flat-square)](https://github.com/thundernest/k-9/releases/latest)
[![Latest beta release](https://img.shields.io/github/v/release/thundernest/k-9.svg?include_prereleases&style=flat-square)](https://github.com/thundernest/k-9/releases)

K-9 Mail is an open-source email client for Android.

## Download

K-9 Mail can be downloaded from a couple of sources:

- [Google Play](https://play.google.com/store/apps/details?id=com.fsck.k9)
- [F-Droid](https://f-droid.org/repository/browse/?fdid=com.fsck.k9)
- [Github Releases](https://github.com/thundernest/k-9/releases)

You might also be interested in becoming a [tester](https://forum.k9mail.app/t/how-do-i-become-a-beta-tester/68) to get an early look at new versions.

## Release Notes

Check out the [Release Notes](https://github.com/thundernest/k-9/wiki/ReleaseNotes) to find out what changed
in each version of K-9 Mail.

## Need Help?

If the app is not behaving like it should, you might find these resources helpful:

- [User Manual](https://docs.k9mail.app/)
- [Frequently Asked Questions](https://forum.k9mail.app/c/faq)
- [Support Forum](https://forum.k9mail.app/)

## Translations

Interested in helping to translate K-9 Mail? Contribute here:

- [K-9 Mail localization](https://explore.transifex.com/k-9/k9mail/)

## Contributing

Thank you for contributing! If you're unfamiliar with the code, start by reading the [developer documentation](docs/DESIGN.md)

Please fork this repository and contribute back using [pull requests](https://github.com/thundernest/k-9/pulls).

Any contributions, large or small, major features, bug fixes, unit/integration tests are welcomed and appreciated
but will be thoroughly reviewed and discussed.
Please make sure you read the [Code Style Guidelines](https://github.com/thundernest/k-9/wiki/CodeStyle).

## Communication

Aside from discussing changes in [pull requests](https://github.com/thundernest/k-9/pulls) and
[issues](https://github.com/thundernest/k-9/issues) we use the following communication services:

- Matrix: [#k9mail:matrix.org](https://matrix.to/#/#tb-android:mozilla.org)
- IRC: [#k9mail on Libera Chat](https://web.libera.chat/#k9mail)
- [Developer mailing list](https://groups.google.com/forum/#!forum/k-9-dev)

## License

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
