#ifndef EXPR_UTILS_H
#define EXPR_UTILS_H

#include "defines.h"
#include "Expr.h"
#include <memory>

namespace ExprUtils {

    /*given an expression ,checks if it a const expr of a SEAM address*/
    inline bool isValidConstExpr(ExprPtr expr, uint64_t &constVal) {
        auto constExpr = std::dynamic_pointer_cast<ConstExpr>(expr);
        if (constExpr) {
            uint64_t value = constExpr->getValue();
            if ((value >> 63) == 1) { 
                constVal = value;
                return true;
            }
        }
        return false;
    }

    inline bool extractConstValues(KVExprPtr expr, uint64_t &constVal) {
        auto addExpr = std::dynamic_pointer_cast<AddExpr>(expr);
        if (!addExpr) return false;  // Not an AddExpr(L, R)

        ExprPtr left = addExpr->getExprPtrL();
        if (isValidConstExpr(left, constVal)) {
            return true;
        }

        ExprPtr right = addExpr->getExprPtrR();
        if (isValidConstExpr(right, constVal)) {
            return true;
        }

        /*If neither L nor R is a valid constant, check for inner Add expressions*/
        if (auto innerAddExpr = std::dynamic_pointer_cast<AddExpr>(left)) {
            ExprPtr innerLeft = innerAddExpr->getExprPtrL();
            ExprPtr innerRight = innerAddExpr->getExprPtrR();

            if (isValidConstExpr(innerLeft, constVal)) {
                return true;
            }
            if (isValidConstExpr(innerRight, constVal)) {
                return true;
            }
        }

        if (auto innerAddExpr = std::dynamic_pointer_cast<AddExpr>(right)) {
            ExprPtr innerLeft = innerAddExpr->getExprPtrL();
            ExprPtr innerRight = innerAddExpr->getExprPtrR();

            if (isValidConstExpr(innerLeft, constVal)) {
                return true;
            }
            if (isValidConstExpr(innerRight, constVal)) {
                return true;
            }
        }
        return false;
    }
}



#endif // EXPR_UTILS_H
