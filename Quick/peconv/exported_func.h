/**
* @file
* @brief Exported Func 类的定义 - 用于存储导出函数的详细信息。与导出解析相关的辅助函数。
*/

#pragma once

#include <windows.h>
#include <string>
#include <algorithm>
#include <set>

namespace peconv {

    /**
   检查指针是否重定向到转发器 - 如果是，则返回长度，否则返回 0。
    */
    size_t forwarder_name_len(BYTE* fPtr); 

    /**
  获取不带扩展名的 DLL 名称
    */
    std::string get_dll_shortname(const std::string& str);

    /**
    从字符串中获取函数名，格式为：DLL name.function name
    */
    std::string get_func_name(const std::string& str);

    /**
   将序数值转换为序数字符串(in a format #[ordinal])
    */
    std::string ordinal_to_string(DWORD func_ordinal);

    /**
    Check if the given string is in a format typical for storing ordinals (#[ordinal])
    */
    bool is_ordinal_string(const std::string& str);

    /**
    Get the ordinal value from the ordinal string (in a format #[ordinal])
    */
    DWORD ordinal_string_to_val(const std::string& str);

    /**
   将函数格式转换为：DLL name.function name 转换为规范化形式(DLL name in lowercase).
    */
    std::string format_dll_func(const std::string& str);

    /**
   存储有关导出函数的信息的类。
    */
    class ExportedFunc
    {
    public:
        /**
        Converts the name to the normalized format.
        */
        static std::string formatName(std::string name);

        //! Compares functions' names. If function is defined by an ordinal, compares ordinals. Does not include the DLL name in the comparison.
        static bool isTheSameFuncName(const peconv::ExportedFunc& func1, const peconv::ExportedFunc& func2);

        //! Compares functions' DLL names.
        static bool isTheSameDllName(const peconv::ExportedFunc& func1, const peconv::ExportedFunc& func2);

        //! Compares functions' names. If function is defined by an ordinal, compares ordinals. Includes the DLL name in the comparison.
        static bool isTheSameFunc(const peconv::ExportedFunc& func1, const peconv::ExportedFunc& func2);

        std::string libName;
        std::string funcName;
        DWORD funcOrdinal;
        bool isByOrdinal;

        //default constructor:
        ExportedFunc() : funcOrdinal(0), isByOrdinal(false) {}

        ExportedFunc(const ExportedFunc& other);
        ExportedFunc(std::string libName, std::string funcName, DWORD funcOrdinal);
        ExportedFunc(std::string libName, DWORD funcOrdinal);
        ExportedFunc(const std::string &forwarderName);

        /**
        Compare two functions with each other.
        Gives the priority to the named functions: if one of the compared functions is unnamed, the named one is treated as smaller.
        If both functions are unnamed, the function with the smaller ordinal is treated as smaller.
        Otherwise, the function with the shorter name is treated as smaller.
        */
        bool operator < (const ExportedFunc& other) const
        {
            //if only one function is named, give the preference to the named one:
            const size_t thisNameLen = this->funcName.length();
            const size_t otherNameLen = other.funcName.length();
            if (thisNameLen == 0 && otherNameLen > 0) {
                return false;
            }
            if (thisNameLen > 0 && otherNameLen == 0) {
                return true;
            }
            //select by shorter lib name:
            int cmp = libName.compare(other.libName);
            if (cmp != 0) {
                return cmp < 0;
            }
            if (thisNameLen == 0 || otherNameLen == 0) {
                return this->funcOrdinal < other.funcOrdinal;
            }
            if (thisNameLen != otherNameLen) {
                return thisNameLen < otherNameLen;
            }
            cmp = funcName.compare(other.funcName);
            return cmp < 0;
        }

        /**
        Gets a string representation of the variable. Full info about the function: library, name, ordinal.
        */
        std::string toString() const;

        /**
        Gets a string representation of the variable. Short info about the function: only function name or ordinal (if the name is missing).
        */
        std::string nameToString() const;

        bool isValid() const
        {
            return (funcName != "" || funcOrdinal != -1);
        }
    };

}; //namespace peconv

