import * as React from "react";
import { cn } from "../../lib/utils";

type Variant = "default" | "brand" | "outline" | "ghost" | "outline-light";
type Size = "default" | "sm" | "lg" | "icon";

const base =
  "inline-flex items-center justify-center gap-2 whitespace-nowrap text-sm font-medium transition-all cursor-pointer select-none " +
  "disabled:pointer-events-none disabled:opacity-50 outline-none focus-visible:ring-2 focus-visible:ring-[#E60000]/40 " +
  "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4";

const variants: Record<Variant, string> = {
  default: "bg-black text-white hover:bg-[#E60000]",
  brand: "bg-[#E60000] text-white hover:bg-[#c50000]",
  outline:
    "border border-gray-300 bg-white text-black hover:border-[#E60000] hover:text-[#E60000]",
  ghost: "text-gray-600 hover:text-[#E60000] hover:bg-gray-100",
  "outline-light":
    "border border-white/40 bg-transparent text-white hover:border-[#E60000] hover:bg-[#E60000] hover:text-white",
};

const sizes: Record<Size, string> = {
  default: "h-10 px-5 py-2",
  sm: "h-8 px-3 text-xs",
  lg: "h-12 px-7 text-base",
  icon: "size-9",
};

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "default", type = "button", ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      className={cn(base, variants[variant], sizes[size], className)}
      {...props}
    />
  ),
);
Button.displayName = "Button";
