package com.fsck.k9.JARL;


public class Matrix {
    private final int numRows;
    private final int numCols;
    private final int[][] data;

    public Matrix(int numRows, int numCols) {
        this.numRows = numRows;
        this.numCols = numCols;
        this.data = new int[numRows][numCols];
    }

    public Matrix(int[][] data) {
        this.numRows = data.length;
        this.numCols = data[0].length;
        this.data = new int[numRows][numCols];
        for (int i = 0; i < numRows; i++) {
            for (int j = 0; j < numCols; j++) {
                this.data[i][j] = data[i][j];
            }
        }
    }

    public Matrix multiply(Matrix other) {
        if (this.numCols != other.numRows) {
            throw new IllegalArgumentException("Matrix dimensions are not compatible for multiplication.");
        }

        Matrix result = new Matrix(this.numRows, other.numCols);
        for (int i = 0; i < this.numRows; i++) {
            for (int j = 0; j < other.numCols; j++) {
                int sum = 0;
                for (int k = 0; k < this.numCols; k++) {
                    sum += this.data[i][k] * other.data[k][j];
                }
                result.data[i][j] = sum;
            }
        }

        return result;
    }

    public Matrix transpose() {
        Matrix result = new Matrix(this.numCols, this.numRows);
        for (int i = 0; i < this.numRows; i++) {
            for (int j = 0; j < this.numCols; j++) {
                result.data[j][i] = this.data[i][j];
            }
        }
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < this.numRows; i++) {
            for (int j = 0; j < this.numCols; j++) {
                sb.append(this.data[i][j]).append(" ");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    public int rows() {
        return this.numRows;
    }

    public int columns() {
        return this.numCols;
    }

    public int getElement(int i, int j) {
        return this.data[i][j];
    }

    public int setElement(int i, int j, int element) {
        this.data[i][j] = element;
        return this.data[i][j];
    }

    public void setRow(int rowIndex, int[] rowElements) {
        if (rowIndex < 0 || rowIndex >= numRows) {
            throw new IllegalArgumentException("Invalid row index.");
        }
        if (rowElements.length != numCols) {
            throw new IllegalArgumentException("Invalid number of elements for row.");
        }
        for (int j = 0; j < numCols; j++) {
            data[rowIndex][j] = rowElements[j];
        }
    }
}

