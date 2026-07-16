#!/bin/bash

# Target directory
SOURCE_DIR="RToolkit"

if [ -d "$SOURCE_DIR" ]; then
    echo "=== Menghapus semua output laporan ==="
    # Hapus semua file laporan html
    rm -f "$SOURCE_DIR"/RToolkit_Report_*.html
    echo "Laporan RToolkit_Report_*.html telah dihapus."

    echo "=== Memindahkan file ke root ==="

    # Pindahkan README.md ke root dengan nama baru
    if [ -f "$SOURCE_DIR/README.md" ]; then
        mv "$SOURCE_DIR/README.md" ./RToolkit_README.md
        echo "RToolkit/README.md dipindahkan ke ./RToolkit_README.md"
    fi

    # Pindahkan sisa file lain ke root
    for file in "$SOURCE_DIR"/*; do
        if [ -e "$file" ]; then
            mv "$file" ./
            echo "Memindahkan $(basename "$file") ke root."
        fi
    done

    # Hapus folder RToolkit jika kosong
    rmdir "$SOURCE_DIR" 2>/dev/null
    if [ ! -d "$SOURCE_DIR" ]; then
        echo "Folder RToolkit berhasil dihapus."
    else
        echo "Folder RToolkit tidak dapat dihapus (mungkin tidak kosong)."
    fi
else
    echo "Folder $SOURCE_DIR tidak ditemukan."
fi
