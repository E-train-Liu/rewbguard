package dk.brics.automaton;

import java.lang.reflect.Array;
import java.util.Arrays;

public class ArrayUtil {
    public static boolean any(boolean[] bools) {
        for (boolean b : bools)
            if (b)
                return true;
        return false;
    }

    public static <T> T[] copyAndAddLast(T[] arr, T obj) {
        int length = arr.length;
        // DEBUG
        // T[] newArr = (T[]) new Object[length + 1];
        T[] newArr = emptyLike(arr, arr.length + 1);
        System.arraycopy(arr, 0, newArr, 0, length);
        newArr[length] = obj;
        return newArr;
    }

    public static <T> T[] copyAndSet(T[] arr, int index, T obj) {
        T[] newArr = arr.clone();
        newArr[index] = obj;
        return newArr;
    }

    public static boolean[] copyAndSet(boolean[] arr, int index, boolean obj) {
        boolean[] newArr = arr.clone();
        newArr[index] = obj;
        return newArr;
    }

    public static <T> T[] copyAndAddAll(T[] arr1, @SuppressWarnings("unchecked") T... arr2) {
        if (arr1.length == 0)
            return arr2.clone();
        if (arr2.length == 0)
            return arr1.clone();
        T[] newArr = emptyLike(arr1, arr1.length + arr2.length);
        System.arraycopy(arr1, 0, newArr, 0, arr1.length);
        System.arraycopy(arr2, 0, newArr, arr1.length, arr2.length);
        return newArr;
    }

    public static <T> T[] concat(T[] arr1, T[] arr2) {
        return copyAndAddAll(arr1, arr2);
    }

    public static int indexOf(int[] arr, int e) {
        for (int i = 0; i < arr.length; ++i)
            if (arr[i] == e)
                return i;
        return -1;
    }

    public static boolean contains(int[] arr, int e) {
        return indexOf(arr, e) >= 0;
    }

    public static <T> T[] emptyLike(T[] arr, int length) {
        Class<T> clazz = (Class<T>) arr.getClass().getComponentType();
        return (T[]) Array.newInstance(clazz, length);
    }

    public static <T> T[] emptyLike(T[] arr) {
        return emptyLike(arr, arr.length);
    }
}
